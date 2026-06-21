#ifndef RIPNET_STATS_H
#define RIPNET_STATS_H

#include <stdint.h>

typedef struct {
    char name[256];
    char description[256];
    char mac_addr[18];
    uint32_t mtu;
    int is_up;
    int is_running;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
} interface_stats_t;

int list_interfaces(interface_stats_t **stats, int *count);
void print_interface_stats(const interface_stats_t *stats);
void free_interface_stats(interface_stats_t *stats, int count);
int get_interface_stats(const char *iface, interface_stats_t *stats);

#endif