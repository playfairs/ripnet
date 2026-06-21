#ifndef RIPNET_ARP_H
#define RIPNET_ARP_H

#include <stdint.h>

typedef struct {
    char ip_address[46];
    char mac_address[18];
    char interface[32];
    char device[64];
    int permanent;
} arp_entry_t;

typedef struct {
    arp_entry_t entries[1024];
    int entry_count;
} arp_table_t;

int arp_table(arp_table_t *table);
int arp_scan(const char *network, arp_table_t *table);
int arp_spoof_detect(const char *interface);
int arp_request(const char *interface, const char *target_ip);
int arp_reply(const char *interface, const char *target_ip, const char *target_mac);
int arp_flush(const char *interface);
int arp_cache_add(const char *interface, const char *ip, const char *mac);
int arp_cache_delete(const char *ip);
void print_arp_table(const arp_table_t *table);

#endif
