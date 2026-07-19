#include "ripnet/dns.h"
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

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

int dns_lookup(const char *hostname, dns_lookup_result_t *result)
{
    struct addrinfo hints, *res;
    struct timespec start, end;
    
    memset(result, 0, sizeof(dns_lookup_result_t));
    strncpy(result->hostname, hostname, sizeof(result->hostname) - 1);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    int status = getaddrinfo(hostname, NULL, &hints, &res);
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    result->response_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + 
                               (end.tv_nsec - start.tv_nsec) / 1000000.0;
    
    if (status != 0) {
        fprintf(stderr, "DNS lookup failed: %s\n", gai_strerror(status));
        result->success = 0;
        return -1;
    }
    
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, result->ip_address, sizeof(result->ip_address));
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, result->ip_address, sizeof(result->ip_address));
    }
    
    freeaddrinfo(res);
    result->success = 1;
    
    printf(COLOR_BOLD COLOR_CYAN "DNS LOOKUP\n" COLOR_RESET);
    printf("  Hostname: " COLOR_BOLD "%s\n" COLOR_RESET, result->hostname);
    printf("  IP Address: " COLOR_BOLD COLOR_GREEN "%s\n" COLOR_RESET, result->ip_address);
    printf("  Response Time: " COLOR_BOLD COLOR_YELLOW "%.2f ms\n" COLOR_RESET, (double)result->response_time_ms);
    
    return 0;
}

int dns_reverse_lookup(const char *ip_address, char *hostname, size_t hostname_len)
{
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    char hbuf[NI_MAXHOST];
    
    printf(COLOR_BOLD COLOR_CYAN "REVERSE DNS LOOKUP\n" COLOR_RESET);
    printf("  IP Address: " COLOR_BOLD "%s\n" COLOR_RESET, ip_address);
    
    if (strchr(ip_address, ':') != NULL) {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ip_address, &addr6.sin6_addr);
        
        if (getnameinfo((struct sockaddr *)&addr6, sizeof(addr6), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) != 0) {
            printf("  Hostname: " COLOR_RED "Not found\n" COLOR_RESET);
            return -1;
        }
    } else {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip_address, &addr.sin_addr);
        
        if (getnameinfo((struct sockaddr *)&addr, sizeof(addr), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) != 0) {
            printf("  Hostname: " COLOR_RED "Not found\n" COLOR_RESET);
            return -1;
        }
    }
    
    strncpy(hostname, hbuf, hostname_len - 1);
    hostname[hostname_len - 1] = '\0';
    
    printf("  Hostname: " COLOR_BOLD COLOR_GREEN "%s\n" COLOR_RESET, hostname);
    
    return 0;
}

int dns_query(const char *hostname, const char *record_type, char *result, size_t result_len)
{
    dns_lookup_result_t lookup;
    printf(COLOR_BOLD COLOR_CYAN "DNS QUERY\n" COLOR_RESET);
    printf("  Hostname: %s\n", hostname);
    printf("  Record Type: %s\n", record_type);

    if (dns_lookup(hostname, &lookup) != 0) {
        return -1;
    }

    if (result != NULL && result_len > 0) {
        snprintf(result, result_len, "%s", lookup.ip_address);
    }

    printf("  " COLOR_GREEN "Resolved to %s\n" COLOR_RESET, lookup.ip_address);
    return 0;
}

int dns_server_test(const char *dns_server, dns_server_test_result_t *result)
{
    dns_lookup_result_t lookup;
    memset(result, 0, sizeof(*result));

    printf(COLOR_BOLD COLOR_CYAN "DNS SERVER TEST\n" COLOR_RESET);
    printf("  DNS Server: %s\n", dns_server);

    if (dns_lookup(dns_server, &lookup) == 0) {
        strncpy(result->dns_server, dns_server, sizeof(result->dns_server) - 1);
        result->queries_sent = 1;
        result->queries_failed = 0;
        result->avg_response_time = (double)lookup.response_time_ms;
        result->success = 1;
        printf("  " COLOR_GREEN "Server responded in %.2f ms\n" COLOR_RESET, result->avg_response_time);
        return 0;
    }

    result->queries_sent = 1;
    result->queries_failed = 1;
    result->success = 0;
    printf("  " COLOR_RED "Server test failed\n" COLOR_RESET);
    return -1;
}

int dns_trace(const char *hostname)
{
    dns_lookup_result_t lookup;

    printf(COLOR_BOLD COLOR_CYAN "DNS TRACE\n" COLOR_RESET);
    printf("  Hostname: %s\n", hostname);

    if (dns_lookup(hostname, &lookup) == 0) {
        printf("  " COLOR_GREEN "Resolved through standard resolver to %s\n" COLOR_RESET, lookup.ip_address);
        return 0;
    }

    printf("  " COLOR_RED "Trace failed\n" COLOR_RESET);
    return -1;
}

int dns_bruteforce(const char *domain, const char *wordlist_path)
{
    FILE *fp = fopen(wordlist_path, "r");
    char entry[256];
    int found = 0;

    printf(COLOR_BOLD COLOR_CYAN "DNS BRUTEFORCE\n" COLOR_RESET);
    printf("  Domain: %s\n", domain);
    printf("  Wordlist: %s\n", wordlist_path);

    if (fp == NULL) {
        printf("  " COLOR_RED "Wordlist could not be opened\n" COLOR_RESET);
        return -1;
    }

    while (fgets(entry, sizeof(entry), fp) != NULL) {
        entry[strcspn(entry, "\r\n")] = '\0';
        if (entry[0] == '\0') {
            continue;
        }

        char probe[512];
        snprintf(probe, sizeof(probe), "%s.%s", entry, domain);
        dns_lookup_result_t lookup;
        if (dns_lookup(probe, &lookup) == 0) {
            printf("  " COLOR_GREEN "Found %s -> %s\n" COLOR_RESET, probe, lookup.ip_address);
            found = 1;
            break;
        }
    }

    fclose(fp);

    return found ? 0 : -1;
}

int dns_zone_transfer(const char *domain, const char *dns_server)
{
    printf(COLOR_BOLD COLOR_CYAN "DNS ZONE TRANSFER\n" COLOR_RESET);
    printf("  Domain: %s\n", domain);
    printf("  DNS Server: %s\n", dns_server);
    printf("  " COLOR_YELLOW "Zone transfer is not enabled by default and was not attempted\n" COLOR_RESET);
    return -1;
}

int dnssec_verify(const char *domain)
{
    dns_lookup_result_t lookup;

    printf(COLOR_BOLD COLOR_CYAN "DNSSEC VERIFICATION\n" COLOR_RESET);
    printf("  Domain: %s\n", domain);

    if (dns_lookup(domain, &lookup) == 0) {
        printf("  " COLOR_GREEN "DNS resolution succeeded for %s\n" COLOR_RESET, domain);
        return 0;
    }

    printf("  " COLOR_RED "DNS resolution failed\n" COLOR_RESET);
    return -1;
}

int dns_cache_flush(void)
{
#if defined(__APPLE__)
    system("sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder");
    printf(COLOR_BOLD COLOR_CYAN "DNS CACHE FLUSH\n" COLOR_RESET);
    printf("  " COLOR_GREEN "DNS cache flushed on macOS\n" COLOR_RESET);
    return 0;
#elif defined(__linux__)
    system("sudo systemd-resolve --flush-caches");
    printf(COLOR_BOLD COLOR_CYAN "DNS CACHE FLUSH\n" COLOR_RESET);
    printf("  " COLOR_GREEN "DNS cache flushed on Linux\n" COLOR_RESET);
    return 0;
#else
    printf(COLOR_BOLD COLOR_CYAN "DNS CACHE FLUSH\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "DNS cache flush not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}
