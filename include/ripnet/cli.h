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
    CMD_SCAN_PROCESSES,
    CMD_DNS_LOOKUP,
    CMD_DNS_REVERSE,
    CMD_DNS_QUERY,
    CMD_DNS_SERVER_TEST,
    CMD_DNS_TRACE,
    CMD_DNS_CACHE_FLUSH,
    CMD_TRACEROUTE,
    CMD_TRACEROUTE_TCP,
    CMD_TRACEROUTE_UDP,
    CMD_PING,
    CMD_PING_TCP,
    CMD_PING_SWEEP,
    CMD_SCAN,
    CMD_SERVICE_SCAN,
    CMD_OS_FINGERPRINT,
    CMD_NETSTAT,
    CMD_NETSTAT_LISTENING,
    CMD_NETSTAT_ROUTE,
    CMD_ARP_TABLE,
    CMD_ARP_SCAN,
    CMD_ARP_FLUSH,
    CMD_ROUTE_TABLE,
    CMD_ROUTE_ADD,
    CMD_ROUTE_DELETE,
    CMD_FIREWALL_LIST,
    CMD_FIREWALL_ADD,
    CMD_FIREWALL_DELETE,
    CMD_FIREWALL_FLUSH,
    CMD_FIREWALL_BLOCK_IP,
    CMD_FIREWALL_UNBLOCK_IP,
    CMD_FIREWALL_BLOCK_PORT,
    CMD_FIREWALL_UNBLOCK_PORT,
    CMD_BANDWIDTH_TEST,
    CMD_BANDWIDTH_MONITOR,
    CMD_MONITOR_START,
    CMD_MONITOR_ALERT,
    CMD_DISCOVERY_PING,
    CMD_DISCOVERY_ARP,
    CMD_SECURITY_SCAN,
    CMD_SECURITY_AUDIT,
    CMD_SECURITY_SSL,
    CMD_SECURITY_SSH,
    CMD_SECURITY_HTTP,
    CMD_SECURITY_SMTP,
    CMD_SECURITY_BANNER
} command_t;

typedef struct {
    command_t cmd;
    char interface[128];
    char filter[512];
    int packet_count;
    int promisc;
    char host[128];
    char hostname[128];
    int port;
    int concurrency;
    int duration;
    int rate_limit;
    char http_path[256];
    int start_port;
    int end_port;
    int timeout;
    int json_output;
    int verbose;
    char process_filter[128];
    int pid_filter;
    char record_type[16];
    char dns_server[128];
    char domain[128];
    char wordlist[256];
    char gateway[128];
    char netmask[128];
    char chain[32];
    char rule[256];
    char ip_address[128];
    char mac_address[32];
    char protocol[16];
    char log_path[256];
    char export_path[256];
    double threshold;
    int count;
    int interval;
} cli_args_t;

int parse_args(int argc, char **argv, cli_args_t *args);
void print_usage(void);
void print_help(void);
void print_version(void);

#endif
