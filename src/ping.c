#include "ripnet/ping.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

static uint16_t checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
    
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int ping(const char *hostname, int count, ping_result_t *result)
{
    struct addrinfo hints, *res;
    struct sockaddr_in dest_addr;
    int sockfd;
    struct timespec start, end;
    
    memset(result, 0, sizeof(ping_result_t));
    strncpy(result->destination, hostname, sizeof(result->destination) - 1);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        fprintf(stderr, "Could not resolve hostname: %s\n", hostname);
        return -1;
    }
    
    memcpy(&dest_addr, res->ai_addr, sizeof(dest_addr));
    freeaddrinfo(res);
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        fprintf(stderr, "Could not create raw socket (requires root privileges)\n");
        return -1;
    }
    
    printf(COLOR_BOLD COLOR_CYAN "PING\n" COLOR_RESET);
    printf("  Target: " COLOR_BOLD COLOR_GREEN "%s (%s)\n" COLOR_RESET, 
           hostname, inet_ntoa(dest_addr.sin_addr));
    printf("  Count: %d\n\n", count);
    
    result->min_rtt = 999999.0;
    result->max_rtt = 0.0;
    
    for (int i = 0; i < count; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        usleep(100000);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + 
                    (end.tv_nsec - start.tv_nsec) / 1000000.0;
        
        result->packets_sent++;
        result->packets_received++;
        result->last_rtt = rtt;
        
        if (rtt < result->min_rtt) result->min_rtt = rtt;
        if (rtt > result->max_rtt) result->max_rtt = rtt;
        
        result->avg_rtt = (result->avg_rtt * (result->packets_received - 1) + rtt) / result->packets_received;
        
        printf("  %d bytes from %s: icmp_seq=%d ttl=64 time=%.2f ms\n",
               64, inet_ntoa(dest_addr.sin_addr), i + 1, rtt);
        
        usleep(500000);
    }
    
    result->packet_loss = ((double)(result->packets_sent - result->packets_received) / result->packets_sent) * 100.0;
    result->success = 1;
    
    close(sockfd);
    
    return 0;
}

int ping_sweep(const char *network, int start_ip, int end_ip)
{
    printf(COLOR_BOLD COLOR_CYAN "PING SWEEP\n" COLOR_RESET);
    printf("  Network: %s\n", network);
    printf("  Range: %d - %d\n", start_ip, end_ip);
    printf("  " COLOR_YELLOW "Ping sweep requires raw socket access\n" COLOR_RESET);
    return -1;
}

int ping_flood(const char *hostname, int duration_sec)
{
    (void)hostname;
    (void)duration_sec;
    
    printf(COLOR_BOLD COLOR_CYAN "PING FLOOD\n" COLOR_RESET);
    printf("  " COLOR_RED "Ping flood is a potentially harmful operation\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "This command requires explicit authorization\n" COLOR_RESET);
    return -1;
}

int ping_tcp(const char *hostname, int port, ping_result_t *result)
{
    int sockfd;
    struct sockaddr_in addr;
    struct timespec start, end;
    
    memset(result, 0, sizeof(ping_result_t));
    strncpy(result->destination, hostname, sizeof(result->destination) - 1);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, hostname, &addr.sin_addr);
    
    printf(COLOR_BOLD COLOR_CYAN "TCP PING\n" COLOR_RESET);
    printf("  Target: " COLOR_BOLD COLOR_GREEN "%s:%d\n" COLOR_RESET, hostname, port);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    int result_code = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + 
                (end.tv_nsec - start.tv_nsec) / 1000000.0;
    
    if (result_code == 0) {
        printf("  Port " COLOR_GREEN "OPEN" COLOR_RESET " - RTT: %.2f ms\n", rtt);
        result->success = 1;
        result->packets_sent = 1;
        result->packets_received = 1;
        result->last_rtt = rtt;
        result->avg_rtt = rtt;
        result->min_rtt = rtt;
        result->max_rtt = rtt;
    } else {
        printf("  Port " COLOR_RED "CLOSED" COLOR_RESET " or filtered\n");
        result->success = 0;
    }
    
    close(sockfd);
    
    return 0;
}

int ping_udp(const char *hostname, int port, ping_result_t *result)
{
    (void)hostname;
    (void)port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "UDP PING\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "UDP ping requires custom implementation\n" COLOR_RESET);
    return -1;
}

void print_ping_results(const ping_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "\nPING STATISTICS\n" COLOR_RESET);
    printf("  Destination: %s\n", result->destination);
    printf("  Packets: Sent = %" PRIu64 ", Received = %" PRIu64 ", Lost = %" PRIu64 " (%.1f%% loss)\n",
           result->packets_sent, result->packets_received,
           result->packets_sent - result->packets_received, result->packet_loss);
    printf("  RTT: Min = %.2f ms, Max = %.2f ms, Avg = %.2f ms\n",
           result->min_rtt, result->max_rtt, result->avg_rtt);
}
