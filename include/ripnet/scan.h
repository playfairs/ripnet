#ifndef RIPNET_SCAN_H
#define RIPNET_SCAN_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int port;
    char state[32];
    char service[64];
    char version[128];
    char banner[256];
} port_info_t;

typedef struct {
    char ip_address[46];
    char hostname[256];
    char mac_address[18];
    port_info_t ports[1024];
    int port_count;
    char os_guess[256];
    int up;
} host_info_t;

typedef struct {
    host_info_t hosts[256];
    int host_count;
    int total_ports_scanned;
    int open_ports_found;
} scan_result_t;

int port_scan(const char *target, int start_port, int end_port, scan_result_t *result);
int service_scan(const char *target, int port, char *service, size_t service_len);
int os_fingerprint(const char *target, char *os, size_t os_len);
int network_scan(const char *network, scan_result_t *result);
int vuln_scan(const char *target, int port);
int udp_scan(const char *target, int start_port, int end_port, scan_result_t *result);
int syn_scan(const char *target, int start_port, int end_port, scan_result_t *result);
int fin_scan(const char *target, int start_port, int end_port, scan_result_t *result);
int xmas_scan(const char *target, int start_port, int end_port, scan_result_t *result);
int null_scan(const char *target, int start_port, int end_port, scan_result_t *result);
void print_scan_results(const scan_result_t *result);

#endif
