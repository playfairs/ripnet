#ifndef RIPNET_BANDWIDTH_H
#define RIPNET_BANDWIDTH_H

#include <stdint.h>

typedef struct {
    char interface[32];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_rate_bps;
    uint64_t tx_rate_bps;
    double rx_rate_mbps;
    double tx_rate_mbps;
    double total_rate_mbps;
} bandwidth_stats_t;

typedef struct {
    bandwidth_stats_t interfaces[32];
    int interface_count;
    double total_bandwidth_mbps;
} bandwidth_result_t;

int bandwidth_test(const char *interface, bandwidth_result_t *result);
int bandwidth_speedtest(const char *server, bandwidth_result_t *result);
int bandwidth_monitor(const char *interface, int interval_sec);
int bandwidth_history(const char *interface, int hours);
int bandwidth_limit(const char *interface, uint64_t max_bps);
int bandwidth_shaper(const char *interface, uint64_t download_bps, uint64_t upload_bps);
void print_bandwidth_results(const bandwidth_result_t *result);

#endif
