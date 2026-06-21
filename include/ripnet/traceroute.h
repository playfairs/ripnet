#ifndef RIPNET_TRACEROUTE_H
#define RIPNET_TRACEROUTE_H

#include <stdint.h>

typedef struct {
    int hop;
    char ip_address[46];
    char hostname[256];
    double rtt1;
    double rtt2;
    double rtt3;
    int success;
} traceroute_hop_t;

typedef struct {
    traceroute_hop_t hops[30];
    int hop_count;
    char destination[256];
    int success;
} traceroute_result_t;

int traceroute(const char *hostname, traceroute_result_t *result);
int traceroute_tcp(const char *hostname, int port, traceroute_result_t *result);
int traceroute_udp(const char *hostname, traceroute_result_t *result);
int traceroute_icmp(const char *hostname, traceroute_result_t *result);
void print_traceroute_results(const traceroute_result_t *result);

#endif
