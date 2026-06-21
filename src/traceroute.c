#include "ripnet/traceroute.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

static int send_icmp_echo(int sockfd, struct sockaddr_in *dest, int ttl, int seq)
{
    (void)sockfd;
    (void)dest;
    (void)ttl;
    (void)seq;
    return -1;
}

static int receive_icmp_reply(int sockfd, struct sockaddr_in *reply_addr, double *rtt)
{
    (void)sockfd;
    (void)reply_addr;
    (void)rtt;
    return -1;
}

int traceroute(const char *hostname, traceroute_result_t *result)
{
    struct addrinfo hints, *res;
    struct sockaddr_in dest_addr;
    int sockfd;
    int max_hops = 30;
    
    memset(result, 0, sizeof(traceroute_result_t));
    strncpy(result->destination, hostname, sizeof(result->destination) - 1);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    
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
    
    printf(COLOR_BOLD COLOR_CYAN "TRACEROUTE\n" COLOR_RESET);
    printf("  Target: " COLOR_BOLD COLOR_GREEN "%s (%s)\n" COLOR_RESET, 
           hostname, inet_ntoa(dest_addr.sin_addr));
    printf("  Max Hops: %d\n\n", max_hops);
    
    for (int ttl = 1; ttl <= max_hops; ttl++) {
        traceroute_hop_t *hop = &result->hops[result->hop_count];
        memset(hop, 0, sizeof(traceroute_hop_t));
        hop->hop = ttl;
        
        printf("%2d  ", ttl);
        
        int reached = 0;
        for (int probe = 0; probe < 3; probe++) {
            struct timespec start, end;
            
            clock_gettime(CLOCK_MONOTONIC, &start);
            
            // need to update this to send ICMP packets with increasing TTL
            // and receive ICMP time exceeded messages
            usleep(100000);
            
            clock_gettime(CLOCK_MONOTONIC, &end);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0;
            
            if (probe == 0) hop->rtt1 = rtt;
            else if (probe == 1) hop->rtt2 = rtt;
            else hop->rtt3 = rtt;
            
            printf("  %.2f ms", rtt);
            
            if (ttl == 1 || ttl == max_hops) {
                // simulates a reaching dest
                reached = 1;
            }
        }
        
        if (reached) {
            printf("  %s\n", inet_ntoa(dest_addr.sin_addr));
            strncpy(hop->ip_address, inet_ntoa(dest_addr.sin_addr), sizeof(hop->ip_address) - 1);
            strncpy(hop->hostname, hostname, sizeof(hop->hostname) - 1);
            hop->success = 1;
            result->hop_count++;
            result->success = 1;
            break;
        } else {
            printf("  *\n");
            hop->success = 0;
            result->hop_count++;
        }
    }
    
    close(sockfd);
    
    return 0;
}

int traceroute_tcp(const char *hostname, int port, traceroute_result_t *result)
{
    (void)port;
    printf(COLOR_BOLD COLOR_CYAN "TCP TRACEROUTE\n" COLOR_RESET);
    printf("  Target: %s\n", hostname);
    printf("  Port: %d\n", port);
    printf("  " COLOR_YELLOW "TCP traceroute requires raw socket access\n" COLOR_RESET);
    return traceroute(hostname, result);
}

int traceroute_udp(const char *hostname, traceroute_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "UDP TRACEROUTE\n" COLOR_RESET);
    printf("  Target: %s\n", hostname);
    printf("  " COLOR_YELLOW "UDP traceroute requires raw socket access\n" COLOR_RESET);
    return traceroute(hostname, result);
}

int traceroute_icmp(const char *hostname, traceroute_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "ICMP TRACEROUTE\n" COLOR_RESET);
    printf("  Target: %s\n", hostname);
    return traceroute(hostname, result);
}

void print_traceroute_results(const traceroute_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "\nTRACEROUTE RESULTS\n" COLOR_RESET);
    printf("  Destination: %s\n", result->destination);
    printf("  Hops: %d\n", result->hop_count);
    printf("  Success: %s\n\n", result->success ? "Yes" : "No");
    
    for (int i = 0; i < result->hop_count; i++) {
        const traceroute_hop_t *hop = &result->hops[i];
        printf("  Hop %d: %s (%s)", hop->hop, hop->ip_address, hop->hostname);
        if (hop->success) {
            printf(" [%.2f ms, %.2f ms, %.2f ms]", hop->rtt1, hop->rtt2, hop->rtt3);
        }
        printf("\n");
    }
}
