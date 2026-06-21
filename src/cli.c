#include "ripnet/cli.h"
#include "ripnet/util.h"
#include "ripnet/stats.h"
#include "ripnet/packet.h"
#include "ripnet/stress.h"
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
    {"json", no_argument, 0, 'j'},
    {"verbose", no_argument, 0, 'v'},
    {"help", no_argument, 0, '?'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0}
};

void print_help(void)
{
    printf("ripnet - Network diagnostics, packet analysis, and load testing toolkit\n\n");
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
    printf("Security Testing:\n");
    printf("  -F, --packet-flood IFACE       Packet flood stress test\n");
    printf("  -S, --port-scan HOST           Port scan\n");
    printf("  -a, --start-port PORT         Start port for scan\n");
    printf("  -e, --end-port PORT           End port for scan\n");
    printf("  -T, --timeout MS               Connection timeout\n");
    printf("  -V, --vuln-scan HOST:PORT      Vulnerability scan\n\n");
    printf("Output:\n");
    printf("  -j, --json                     Output in JSON format\n");
    printf("  -v, --verbose                  Verbose output\n");
    printf("  -?, --help                     Show this help message\n");
    printf("  --version                      Show version information\n\n");
    printf("Examples:\n");
    printf("  ripnet --list-interfaces\n");
    printf("  ripnet --capture eth0 --filter \"tcp port 80\"\n");
    printf("  ripnet --tcp-stress example.com --port 80 --concurrency 10 --duration 30\n");
    printf("  ripnet --port-scan 192.168.1.1 --start-port 1 --end-port 1000\n");
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

    while ((opt = getopt_long(argc, argv, "ls:c:f:n:pt:h:P:C:D:R:H:F:S:a:e:T:V:jv?", long_options, &option_index)) != -1) {
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
            case 'j':
                args->json_output = 1;
                break;
            case 'v':
                args->verbose = 1;
                break;
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