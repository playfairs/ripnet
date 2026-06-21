#ifndef RIPNET_NETSTAT_H
#define RIPNET_NETSTAT_H

#include <stdint.h>

typedef struct {
    char protocol[16];
    char local_address[64];
    char remote_address[64];
    char state[32];
    int pid;
    char process_name[256];
    uint64_t bytes_sent;
    uint64_t bytes_received;
} connection_info_t;

typedef struct {
    connection_info_t connections[4096];
    int connection_count;
    int tcp_count;
    int udp_count;
    int listening_count;
    int established_count;
} netstat_result_t;

int netstat_connections(netstat_result_t *result);
int netstat_listening(netstat_result_t *result);
int netstat_process(int pid, netstat_result_t *result);
int netstat_route(void);
int netstat_interface(const char *iface);
int netstat_group(const char *group);
int netstat_timer(void);
void print_netstat_results(const netstat_result_t *result);

#endif
