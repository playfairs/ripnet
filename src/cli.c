#include "ripnet/cli.h"
#include "ripnet/util.h"
#include "ripnet/stats.h"
#include "ripnet/packet.h"
#include "ripnet/stress.h"
#include "ripnet/dns.h"
#include "ripnet/traceroute.h"
#include "ripnet/ping.h"
#include "ripnet/scan.h"
#include "ripnet/netstat.h"
#include "ripnet/arp.h"
#include "ripnet/route.h"
#include "ripnet/firewall.h"
#include "ripnet/bandwidth.h"
#include "ripnet/monitor.h"
#include "ripnet/discovery.h"
#include "ripnet/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static struct option long_options[] = {
    {"list-interfaces", no_argument, 0, 'l'},
    {"show-stats", required_argument, 0, 's'},
    {"capture", required_argument, 0, 'c'},
    {"filter", required_argument, 0, 'f'},
    {"count", required_argument, 0, 'n'},
    {"promisc", no_argument, 0, 'p'},
    {"tcp-stress", required_argument, 0, 't'},
    {"http-stress", required_argument, 0, 'h'},
    {"port", required_argument, 0, 'P'},
    {"concurrency", required_argument, 0, 'C'},
    {"duration", required_argument, 0, 'D'},
    {"rate-limit", required_argument, 0, 'R'},
    {"http-path", required_argument, 0, 'H'},
    {"packet-flood", required_argument, 0, 'F'},
    {"port-scan", required_argument, 0, 'S'},
    {"start-port", required_argument, 0, 'a'},
    {"end-port", required_argument, 0, 'e'},
    {"timeout", required_argument, 0, 'T'},
    {"vuln-scan", required_argument, 0, 'V'},
    {"scan-processes", no_argument, 0, 'N'},
    {"process", required_argument, 0, 'X'},
    {"pid", required_argument, 0, 'I'},
    {"dns-lookup", required_argument, 0, 'd'},
    {"dns-reverse", required_argument, 0, 'r'},
    {"dns-query", required_argument, 0, 'q'},
    {"dns-server", required_argument, 0, 'Z'},
    {"dns-trace", required_argument, 0, 'Y'},
    {"dns-cache-flush", no_argument, 0, 'Q'},
    {"traceroute", required_argument, 0, 'g'},
    {"traceroute-tcp", required_argument, 0, 'G'},
    {"traceroute-udp", required_argument, 0, 'U'},
    {"ping", required_argument, 0, 'i'},
    {"ping-tcp", required_argument, 0, 'J'},
    {"ping-count", required_argument, 0, 'K'},
    {"scan", required_argument, 0, 'M'},
    {"service-scan", required_argument, 0, 'O'},
    {"os-fingerprint", required_argument, 0, 'B'},
    {"netstat", no_argument, 0, 'E'},
    {"netstat-listening", no_argument, 0, 'L'},
    {"netstat-route", no_argument, 0, 'W'},
    {"arp-table", no_argument, 0, 'A'},
    {"arp-scan", required_argument, 0, 'y'},
    {"arp-flush", required_argument, 0, 'z'},
    {"route-table", no_argument, 0, 'o'},
    {"route-add", required_argument, 0, '1'},
    {"route-delete", required_argument, 0, '2'},
    {"gateway", required_argument, 0, '3'},
    {"netmask", required_argument, 0, '4'},
    {"firewall-list", no_argument, 0, '5'},
    {"firewall-add", required_argument, 0, '6'},
    {"firewall-delete", required_argument, 0, '7'},
    {"firewall-flush", required_argument, 0, '8'},
    {"chain", required_argument, 0, '9'},
    {"block-ip", required_argument, 0, '!'},
    {"unblock-ip", required_argument, 0, '@'},
    {"block-port", required_argument, 0, '#'},
    {"unblock-port", required_argument, 0, '$'},
    {"bandwidth-test", required_argument, 0, '%'},
    {"bandwidth-monitor", required_argument, 0, '^'},
    {"monitor-start", required_argument, 0, '&'},
    {"monitor-alert", required_argument, 0, '*'},
    {"threshold", required_argument, 0, '('},
    {"discovery-ping", required_argument, 0, ')'},
    {"discovery-arp", required_argument, 0, '_'},
    {"security-scan", required_argument, 0, '+'},
    {"security-audit", required_argument, 0, '-'},
    {"security-ssl", required_argument, 0, '='},
    {"security-ssh", required_argument, 0, '['},
    {"security-http", required_argument, 0, ']'},
    {"security-smtp", required_argument, 0, '{'},
    {"security-banner", required_argument, 0, '}'},
    {"json", no_argument, 0, 'j'},
    {"verbose", no_argument, 0, 'v'},
    {"help", no_argument, 0, '?'},
    {"version", no_argument, 0, 'w'},
    {0, 0, 0, 0}
};

void print_help(void)
{
    printf("ripnet - Advanced Network Diagnostics, Security, and Analysis Toolkit\n\n");
    printf("Usage: ripnet [OPTIONS]\n\n");
    printf("Interface Discovery:\n");
    printf("  -l, --list-interfaces          List all network interfaces\n");
    printf("  -s, --show-stats IFACE         Show statistics for interface\n\n");
    printf("Packet Capture:\n");
    printf("  -c, --capture IFACE            Start packet capture on interface\n");
    printf("  -f, --filter FILTER            BPF filter expression\n");
    printf("  -n, --count N                  Capture N packets then exit\n");
    printf("  -p, --promisc                  Enable promiscuous mode\n\n");
    printf("Load Testing:\n");
    printf("  -t, --tcp-stress HOST          Run TCP stress test\n");
    printf("  -h, --http-stress HOST         Run HTTP stress test\n");
    printf("  -P, --port PORT                Target port\n");
    printf("  -C, --concurrency N            Number of concurrent connections\n");
    printf("  -D, --duration SECONDS         Test duration\n");
    printf("  -R, --rate-limit N             Rate limit (connections/sec)\n");
    printf("  -H, --http-path PATH           HTTP path for stress test\n\n");
    printf("DNS Tools:\n");
    printf("  -d, --dns-lookup HOST          DNS lookup\n");
    printf("  -r, --dns-reverse IP           Reverse DNS lookup\n");
    printf("  -q, --dns-query HOST TYPE     DNS query (A, AAAA, MX, etc.)\n");
    printf("  -Z, --dns-server SERVER        DNS server for queries\n");
    printf("  -Y, --dns-trace HOST           DNS trace\n");
    printf("  -Q, --dns-cache-flush          Flush DNS cache\n\n");
    printf("Network Tracing:\n");
    printf("  -g, --traceroute HOST          Traceroute to host\n");
    printf("  -G, --traceroute-tcp HOST     TCP traceroute\n");
    printf("  -U, --traceroute-udp HOST     UDP traceroute\n\n");
    printf("Ping Tools:\n");
    printf("  -i, --ping HOST                Ping host\n");
    printf("  -J, --ping-tcp HOST:PORT       TCP ping\n");
    printf("  -K, --ping-count N             Number of pings\n\n");
    printf("Scanning:\n");
    printf("  -M, --scan HOST                Port scan\n");
    printf("  -O, --service-scan HOST:PORT   Service scan\n");
    printf("  -B, --os-fingerprint HOST       OS fingerprinting\n");
    printf("  -a, --start-port PORT         Start port for scan\n");
    printf("  -e, --end-port PORT           End port for scan\n");
    printf("  -T, --timeout MS               Connection timeout\n\n");
    printf("Network Statistics:\n");
    printf("  -E, --netstat                  Show network connections\n");
    printf("  -L, --netstat-listening        Show listening ports\n");
    printf("  -W, --netstat-route            Show routing table\n\n");
    printf("ARP Tools:\n");
    printf("  -A, --arp-table                Show ARP table\n");
    printf("  -y, --arp-scan NETWORK         ARP scan network\n");
    printf("  -z, --arp-flush IFACE          Flush ARP cache\n\n");
    printf("Routing:\n");
    printf("  -o, --route-table              Show routing table\n");
    printf("  -1, --route-add DEST           Add route\n");
    printf("  -2, --route-delete DEST        Delete route\n");
    printf("  -3, --gateway GATEWAY          Gateway for route\n");
    printf("  -4, --netmask NETMASK          Netmask for route\n\n");
    printf("Firewall:\n");
    printf("  -5, --firewall-list            List firewall rules\n");
    printf("  -6, --firewall-add RULE        Add firewall rule\n");
    printf("  -7, --firewall-delete RULE     Delete firewall rule\n");
    printf("  -8, --firewall-flush CHAIN     Flush firewall chain\n");
    printf("  -9, --chain CHAIN              Firewall chain\n");
    printf("  --block-ip IP                  Block IP address\n");
    printf("  --unblock-ip IP                Unblock IP address\n");
    printf("  --block-port PORT PROTO        Block port\n");
    printf("  --unblock-port PORT PROTO      Unblock port\n\n");
    printf("Bandwidth:\n");
    printf("  --bandwidth-test IFACE         Test bandwidth\n");
    printf("  --bandwidth-monitor IFACE      Monitor bandwidth\n\n");
    printf("Monitoring:\n");
    printf("  --monitor-start IFACE          Start network monitor\n");
    printf("  --monitor-alert IFACE          Monitor with alerts\n");
    printf("  --threshold MBPS              Alert threshold\n\n");
    printf("Discovery:\n");
    printf("  --discovery-ping NETWORK       Ping discovery\n");
    printf("  --discovery-arp NETWORK       ARP discovery\n\n");
    printf("Security:\n");
    printf("  --security-scan HOST           Security scan\n");
    printf("  --security-audit HOST          Security audit\n");
    printf("  --security-ssl HOST:PORT       SSL security check\n");
    printf("  --security-ssh HOST:PORT       SSH security check\n");
    printf("  --security-http HOST:PORT      HTTP security check\n");
    printf("  --security-smtp HOST:PORT      SMTP security check\n");
    printf("  --security-banner HOST:PORT    Banner grab\n\n");
    printf("Process Scanning:\n");
    printf("  -N, --scan-processes           Scan network processes\n");
    printf("  -X, --process NAME             Filter by process name\n");
    printf("  -I, --pid PID                  Filter by PID\n\n");
    printf("Output:\n");
    printf("  -j, --json                     Output in JSON format\n");
    printf("  -v, --verbose                  Verbose output\n");
    printf("  -?, --help                     Show this help message\n");
    printf("  -w, --version                  Show version information\n\n");
    printf("Examples:\n");
    printf("  ripnet --list-interfaces\n");
    printf("  ripnet --dns-lookup example.com\n");
    printf("  ripnet --traceroute example.com\n");
    printf("  ripnet --ping example.com --ping-count 5\n");
    printf("  ripnet --scan 192.168.1.1 --start-port 1 --end-port 1000\n");
    printf("  ripnet --arp-table\n");
    printf("  ripnet --firewall-list\n");
    printf("  ripnet --bandwidth-test eth0\n");
    printf("  ripnet --security-ssh example.com:22\n");
}

void print_version(void)
{
    printf("ripnet version 1.0.0\n");
    printf("License: GPL-3.0-only\n");
}

int parse_args(int argc, char **argv, cli_args_t *args)
{
    int opt;
    int option_index = 0;

    memset(args, 0, sizeof(cli_args_t));
    args->port = 80;
    args->concurrency = 1;
    args->duration = 10;
    args->rate_limit = 0;
    args->start_port = 1;
    args->end_port = 1024;
    args->timeout = 1000;
    args->promisc = 0;
    args->pid_filter = 0;
    args->count = 4;
    args->interval = 1;
    args->threshold = 100.0;

    while ((opt = getopt_long(argc, argv, "ls:c:f:n:pt:h:P:C:D:R:H:F:S:a:e:T:V:NX:I:jv?d:r:q:Z:Y:Qg:G:Ui:J:K:M:O:B:ELWA:y:z:o:1:2:3:4:5:6:7:8:9:!:@:#:$:%:^:&:*:(:)'):_:+:-:=:[:]:{:}w", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l':
                args->cmd = CMD_LIST_INTERFACES;
                break;
            case 's':
                args->cmd = CMD_SHOW_STATS;
                strncpy(args->interface, optarg, 255);
                break;
            case 'c':
                args->cmd = CMD_CAPTURE;
                strncpy(args->interface, optarg, 255);
                break;
            case 'f':
                strncpy(args->filter, optarg, 1023);
                break;
            case 'n':
                if (parse_uint(optarg, (unsigned int *)&args->packet_count) < 0) {
                    fprintf(stderr, "Invalid packet count: %s\n", optarg);
                    return -1;
                }
                break;
            case 'p':
                args->promisc = 1;
                break;
            case 't':
                args->cmd = CMD_TCP_STRESS;
                strncpy(args->host, optarg, 255);
                break;
            case 'h':
                args->cmd = CMD_HTTP_STRESS;
                strncpy(args->host, optarg, 255);
                break;
            case 'P':
                if (parse_uint(optarg, (unsigned int *)&args->port) < 0) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return -1;
                }
                break;
            case 'C':
                if (parse_uint(optarg, (unsigned int *)&args->concurrency) < 0) {
                    fprintf(stderr, "Invalid concurrency: %s\n", optarg);
                    return -1;
                }
                break;
            case 'D':
                if (parse_uint(optarg, (unsigned int *)&args->duration) < 0) {
                    fprintf(stderr, "Invalid duration: %s\n", optarg);
                    return -1;
                }
                break;
            case 'R':
                if (parse_uint(optarg, (unsigned int *)&args->rate_limit) < 0) {
                    fprintf(stderr, "Invalid rate limit: %s\n", optarg);
                    return -1;
                }
                break;
            case 'H':
                strncpy(args->http_path, optarg, 511);
                break;
            case 'F':
                args->cmd = CMD_PACKET_FLOOD;
                strncpy(args->interface, optarg, 255);
                break;
            case 'S':
                args->cmd = CMD_PORT_SCAN;
                strncpy(args->host, optarg, 255);
                break;
            case 'a':
                if (parse_uint(optarg, (unsigned int *)&args->start_port) < 0) {
                    fprintf(stderr, "Invalid start port: %s\n", optarg);
                    return -1;
                }
                break;
            case 'e':
                if (parse_uint(optarg, (unsigned int *)&args->end_port) < 0) {
                    fprintf(stderr, "Invalid end port: %s\n", optarg);
                    return -1;
                }
                break;
            case 'T':
                if (parse_uint(optarg, (unsigned int *)&args->timeout) < 0) {
                    fprintf(stderr, "Invalid timeout: %s\n", optarg);
                    return -1;
                }
                break;
            case 'V':
                if (strstr(optarg, ":") != NULL) {
                    args->cmd = CMD_VULN_SCAN;
                    char *colon = strchr(optarg, ':');
                    strncpy(args->host, optarg, colon - optarg);
                    args->port = atoi(colon + 1);
                } else {
                    print_version();
                    exit(0);
                }
                break;
            case 'N':
                args->cmd = CMD_SCAN_PROCESSES;
                break;
            case 'X':
                strncpy(args->process_filter, optarg, 255);
                break;
            case 'I':
                if (parse_uint(optarg, (unsigned int *)&args->pid_filter) < 0) {
                    fprintf(stderr, "Invalid PID: %s\n", optarg);
                    return -1;
                }
                break;
            case 'd':
                args->cmd = CMD_DNS_LOOKUP;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'r':
                args->cmd = CMD_DNS_REVERSE;
                strncpy(args->ip_address, optarg, 255);
                break;
            case 'q':
                args->cmd = CMD_DNS_QUERY;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'Z':
                strncpy(args->dns_server, optarg, 255);
                break;
            case 'Y':
                args->cmd = CMD_DNS_TRACE;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'Q':
                args->cmd = CMD_DNS_CACHE_FLUSH;
                break;
            case 'g':
                args->cmd = CMD_TRACEROUTE;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'G':
                args->cmd = CMD_TRACEROUTE_TCP;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'U':
                args->cmd = CMD_TRACEROUTE_UDP;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'i':
                args->cmd = CMD_PING;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'J':
                args->cmd = CMD_PING_TCP;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'K':
                if (parse_uint(optarg, (unsigned int *)&args->count) < 0) {
                    fprintf(stderr, "Invalid ping count: %s\n", optarg);
                    return -1;
                }
                break;
            case 'M':
                args->cmd = CMD_SCAN;
                strncpy(args->host, optarg, 255);
                break;
            case 'O':
                args->cmd = CMD_SERVICE_SCAN;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'B':
                args->cmd = CMD_OS_FINGERPRINT;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'E':
                args->cmd = CMD_NETSTAT;
                break;
            case 'L':
                args->cmd = CMD_NETSTAT_LISTENING;
                break;
            case 'W':
                args->cmd = CMD_NETSTAT_ROUTE;
                break;
            case 'A':
                args->cmd = CMD_ARP_TABLE;
                break;
            case 'y':
                args->cmd = CMD_ARP_SCAN;
                strncpy(args->domain, optarg, 255);
                break;
            case 'z':
                args->cmd = CMD_ARP_FLUSH;
                strncpy(args->interface, optarg, 255);
                break;
            case 'o':
                args->cmd = CMD_ROUTE_TABLE;
                break;
            case '1':
                args->cmd = CMD_ROUTE_ADD;
                strncpy(args->host, optarg, 255);
                break;
            case '2':
                args->cmd = CMD_ROUTE_DELETE;
                strncpy(args->host, optarg, 255);
                break;
            case '3':
                strncpy(args->gateway, optarg, 255);
                break;
            case '4':
                strncpy(args->netmask, optarg, 255);
                break;
            case '5':
                args->cmd = CMD_FIREWALL_LIST;
                break;
            case '6':
                args->cmd = CMD_FIREWALL_ADD;
                strncpy(args->rule, optarg, 511);
                break;
            case '7':
                args->cmd = CMD_FIREWALL_DELETE;
                strncpy(args->rule, optarg, 511);
                break;
            case '8':
                args->cmd = CMD_FIREWALL_FLUSH;
                strncpy(args->chain, optarg, 63);
                break;
            case '9':
                strncpy(args->chain, optarg, 63);
                break;
            case '!':
                args->cmd = CMD_FIREWALL_BLOCK_IP;
                strncpy(args->ip_address, optarg, 255);
                break;
            case '@':
                args->cmd = CMD_FIREWALL_UNBLOCK_IP;
                strncpy(args->ip_address, optarg, 255);
                break;
            case '#':
                args->cmd = CMD_FIREWALL_BLOCK_PORT;
                if (parse_uint(optarg, (unsigned int *)&args->port) < 0) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return -1;
                }
                break;
            case '$':
                args->cmd = CMD_FIREWALL_UNBLOCK_PORT;
                if (parse_uint(optarg, (unsigned int *)&args->port) < 0) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return -1;
                }
                break;
            case '%':
                args->cmd = CMD_BANDWIDTH_TEST;
                strncpy(args->interface, optarg, 255);
                break;
            case '^':
                args->cmd = CMD_BANDWIDTH_MONITOR;
                strncpy(args->interface, optarg, 255);
                break;
            case '&':
                args->cmd = CMD_MONITOR_START;
                strncpy(args->interface, optarg, 255);
                break;
            case '*':
                args->cmd = CMD_MONITOR_ALERT;
                strncpy(args->interface, optarg, 255);
                break;
            case '(':
                args->threshold = atof(optarg);
                break;
            case ')':
                args->cmd = CMD_DISCOVERY_PING;
                strncpy(args->domain, optarg, 255);
                break;
            case '_':
                args->cmd = CMD_DISCOVERY_ARP;
                strncpy(args->domain, optarg, 255);
                break;
            case '+':
                args->cmd = CMD_SECURITY_SCAN;
                strncpy(args->hostname, optarg, 255);
                break;
            case '-':
                args->cmd = CMD_SECURITY_AUDIT;
                strncpy(args->hostname, optarg, 255);
                break;
            case '=':
                args->cmd = CMD_SECURITY_SSL;
                strncpy(args->hostname, optarg, 255);
                break;
            case '[':
                args->cmd = CMD_SECURITY_SSH;
                strncpy(args->hostname, optarg, 255);
                break;
            case ']':
                args->cmd = CMD_SECURITY_HTTP;
                strncpy(args->hostname, optarg, 255);
                break;
            case '{':
                args->cmd = CMD_SECURITY_SMTP;
                strncpy(args->hostname, optarg, 255);
                break;
            case '}':
                args->cmd = CMD_SECURITY_BANNER;
                strncpy(args->hostname, optarg, 255);
                break;
            case 'j':
                args->json_output = 1;
                break;
            case 'v':
                args->verbose = 1;
                break;
            case 'w':
                print_version();
                exit(0);
            case '?':
                print_help();
                exit(0);
            default:
                print_help();
                return -1;
        }
    }

    if (args->cmd == CMD_NONE) {
        print_help();
        return -1;
    }

    return 0;
}