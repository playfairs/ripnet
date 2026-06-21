#ifndef RIPNET_DNS_H
#define RIPNET_DNS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char hostname[256];
    char ip_address[46];
    uint64_t response_time_ms;
    int success;
} dns_lookup_result_t;

typedef struct {
    char dns_server[46];
    int queries_sent;
    int queries_failed;
    double avg_response_time;
    int success;
} dns_server_test_result_t;

int dns_lookup(const char *hostname, dns_lookup_result_t *result);
int dns_reverse_lookup(const char *ip_address, char *hostname, size_t hostname_len);
int dns_query(const char *hostname, const char *record_type, char *result, size_t result_len);
int dns_server_test(const char *dns_server, dns_server_test_result_t *result);
int dns_trace(const char *hostname);
int dns_bruteforce(const char *domain, const char *wordlist_path);
int dns_zone_transfer(const char *domain, const char *dns_server);
int dnssec_verify(const char *domain);
int dns_cache_flush(void);

#endif
