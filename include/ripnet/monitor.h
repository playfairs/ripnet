#ifndef RIPNET_MONITOR_H
#define RIPNET_MONITOR_H

#include <stdint.h>

typedef struct {
    char interface[32];
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    double rx_rate_mbps;
    double tx_rate_mbps;
    double packet_loss;
} monitor_stats_t;

typedef struct {
    monitor_stats_t current;
    monitor_stats_t previous;
    double cpu_usage;
    double memory_usage;
    int connection_count;
} monitor_snapshot_t;

int monitor_start(const char *interface);
int monitor_stop(void);
int monitor_status(monitor_snapshot_t *snapshot);
int monitor_alert(const char *interface, double threshold_mbps);
int monitor_log(const char *interface, const char *log_path);
int monitor_export(const char *interface, const char *export_path);
void print_monitor_status(const monitor_snapshot_t *snapshot);

#endif
