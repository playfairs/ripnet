#include "ripnet/scan.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

static const char *common_services[] = {
    "ftp", "ssh", "telnet", "smtp", "domain", "http", "pop3", "imap", "https",
    "microsoft-ds", "mysql", "postgres", "rdp", "svn", "winrm", NULL
};

static const int common_ports[] = {
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    445, 3306, 5432, 3389, 3690, 5985, 0
};

static const char *get_service_name(int port)
{
    for (int i = 0; common_ports[i] != 0; i++) {
        if (port == common_ports[i]) {
            return common_services[i];
        }
    }
    return "unknown";
}

int port_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    struct sockaddr_in addr;
    int sockfd;
    struct timeval timeout;
    fd_set fdset;
    
    memset(result, 0, sizeof(scan_result_t));
    strncpy(result->hosts[0].ip_address, target, sizeof(result->hosts[0].ip_address) - 1);
    result->host_count = 1;
    
    printf(COLOR_BOLD COLOR_CYAN "PORT SCAN\n" COLOR_RESET);
    printf("  Target: " COLOR_BOLD COLOR_GREEN "%s\n" COLOR_RESET, target);
    printf("  Port Range: %d-%d\n\n", start_port, end_port);
    
    for (int port = start_port; port <= end_port; port++) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            continue;
        }
        
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target, &addr.sin_addr);
        
        connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        
        if (select(sockfd + 1, NULL, &fdset, NULL, &timeout) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                port_info_t *pinfo = &result->hosts[0].ports[result->hosts[0].port_count];
                pinfo->port = port;
                strcpy(pinfo->state, "open");
                strcpy(pinfo->service, get_service_name(port));
                strcpy(pinfo->version, "unknown");
                strcpy(pinfo->banner, "");
                
                printf("  Port " COLOR_BOLD COLOR_GREEN "%d" COLOR_RESET " %s %s\n", 
                       port, pinfo->state, pinfo->service);
                
                result->hosts[0].port_count++;
                result->open_ports_found++;
            }
        }
        
        close(sockfd);
        result->total_ports_scanned++;
    }
    
    printf("\n  " COLOR_BOLD "Scan complete: %d open ports found\n" COLOR_RESET, result->open_ports_found);
    
    return 0;
}

int service_scan(const char *target, int port, char *service, size_t service_len)
{
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024];
    ssize_t bytes;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    printf(COLOR_BOLD COLOR_CYAN "SERVICE SCAN\n" COLOR_RESET);
    printf("  Target: %s:%d\n", target, port);
    
    bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("  Banner: %s\n", buffer);
        strncpy(service, buffer, service_len - 1);
        service[service_len - 1] = '\0';
    } else {
        strcpy(service, get_service_name(port));
    }
    
    close(sockfd);
    
    return 0;
}

int os_fingerprint(const char *target, char *os, size_t os_len)
{
    (void)target;
    
    printf(COLOR_BOLD COLOR_CYAN "OS FINGERPRINTING\n" COLOR_RESET);
    printf("  Target: %s\n", target);
    printf("  " COLOR_YELLOW "OS fingerprinting requires active probing and passive analysis\n" COLOR_RESET);
    
    strncpy(os, "Unknown", os_len - 1);
    os[os_len - 1] = '\0';
    
    return -1;
}

int network_scan(const char *network, scan_result_t *result)
{
    (void)result;
    printf(COLOR_BOLD COLOR_CYAN "NETWORK SCAN\n" COLOR_RESET);
    printf("  Network: %s\n", network);
    printf("  " COLOR_YELLOW "Network scan requires CIDR parsing and host enumeration\n" COLOR_RESET);
    return -1;
}

int vuln_scan(const char *target, int port)
{
    printf(COLOR_BOLD COLOR_CYAN "VULNERABILITY SCAN\n" COLOR_RESET);
    printf("  Target: %s:%d\n", target, port);
    printf("  " COLOR_YELLOW "Vulnerability scan requires vulnerability database\n" COLOR_RESET);
    return -1;
}

int udp_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    (void)target;
    (void)start_port;
    (void)end_port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "UDP SCAN\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "UDP scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

int syn_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    (void)target;
    (void)start_port;
    (void)end_port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "SYN SCAN\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "SYN scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

int fin_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    (void)target;
    (void)start_port;
    (void)end_port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "FIN SCAN\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "FIN scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

int xmas_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    (void)target;
    (void)start_port;
    (void)end_port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "XMAS SCAN\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "XMAS scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

int null_scan(const char *target, int start_port, int end_port, scan_result_t *result)
{
    (void)target;
    (void)start_port;
    (void)end_port;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "NULL SCAN\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "NULL scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

void print_scan_results(const scan_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "\nSCAN RESULTS\n" COLOR_RESET);
    printf("  Hosts scanned: %d\n", result->host_count);
    printf("  Ports scanned: %d\n", result->total_ports_scanned);
    printf("  Open ports found: %d\n\n", result->open_ports_found);
    
    for (int i = 0; i < result->host_count; i++) {
        const host_info_t *host = &result->hosts[i];
        printf("  Host: %s (%s)\n", host->ip_address, host->hostname);
        printf("  MAC: %s\n", host->mac_address);
        printf("  Status: %s\n", host->up ? "UP" : "DOWN");
        printf("  OS Guess: %s\n", host->os_guess);
        printf("  Open Ports:\n");
        
        for (int j = 0; j < host->port_count; j++) {
            const port_info_t *port = &host->ports[j];
            printf("    %d/%s %s %s %s\n", port->port, "tcp", port->state, 
                   port->service, port->version);
        }
        
        printf("\n");
    }
}
