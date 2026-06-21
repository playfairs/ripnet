#ifndef RIPNET_PING_H
#define RIPNET_PING_H

#include <stdint.h>

typedef struct {
    char destination[256];
    uint64_t packets_sent;
    uint64_t packets_received;
    double packet_loss;
    double min_rtt;
    double max_rtt;
    double avg_rtt;
    double last_rtt;
    int success;
} ping_result_t;

int ping(const char *hostname, int count, ping_result_t *result);
int ping_sweep(const char *network, int start_ip, int end_ip);
int ping_flood(const char *hostname, int duration_sec);
int ping_tcp(const char *hostname, int port, ping_result_t *result);
int ping_udp(const char *hostname, int port, ping_result_t *result);
void print_ping_results(const ping_result_t *result);

#endif
