#ifndef RIPNET_CLI_H
#define RIPNET_CLI_H

typedef enum {
    CMD_NONE,
    CMD_LIST_INTERFACES,
    CMD_SHOW_STATS,
    CMD_CAPTURE,
    CMD_TCP_STRESS,
    CMD_HTTP_STRESS,
    CMD_PACKET_FLOOD,
    CMD_PORT_SCAN,
    CMD_VULN_SCAN,
    CMD_SCAN_PROCESSES
} command_t;

typedef struct {
    command_t cmd;
    char interface[256];
    char filter[1024];
    int packet_count;
    int promisc;
    char host[256];
    int port;
    int concurrency;
    int duration;
    int rate_limit;
    char http_path[512];
    int start_port;
    int end_port;
    int timeout;
    int json_output;
    int verbose;
    char process_filter[256];
    int pid_filter;
} cli_args_t;

int parse_args(int argc, char **argv, cli_args_t *args);
void print_help(void);
void print_version(void);

#endif