#ifndef RIPNET_DISCOVERY_H
#define RIPNET_DISCOVERY_H

#include <stdint.h>

typedef struct {
    char ip_address[46];
    char hostname[256];
    char mac_address[18];
    char vendor[128];
    int up;
    int ports_open[1024];
    int port_count;
    char services[256][64];
    int service_count;
} discovered_host_t;

typedef struct {
    discovered_host_t hosts[1024];
    int host_count;
    char network[64];
} discovery_result_t;

int discovery_ping(const char *network, discovery_result_t *result);
int discovery_arp(const char *network, discovery_result_t *result);
int discovery_dns(const char *domain, discovery_result_t *result);
int discovery_snmp(const char *network, discovery_result_t *result);
int discovery_upnp(const char *network, discovery_result_t *result);
int discovery_mdns(const char *network, discovery_result_t *result);
int discovery_llmnr(const char *network, discovery_result_t *result);
int discovery_netbios(const char *network, discovery_result_t *result);
int discovery_smb(const char *network, discovery_result_t *result);
int discovery_http(const char *network, discovery_result_t *result);
int discovery_ssl(const char *network, discovery_result_t *result);
void print_discovery_results(const discovery_result_t *result);

#endif
