#include "ripnet/cli.h"
#include "ripnet/stats.h"
#include "ripnet/packet.h"
#include "ripnet/stress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    cli_args_t args;

    if (parse_args(argc, argv, &args) < 0) {
        return 1;
    }

    switch (args.cmd) {
        case CMD_LIST_INTERFACES: {
            interface_stats_t *stats;
            int count;

            if (list_interfaces(&stats, &count) < 0) {
                fprintf(stderr, "Failed to list interfaces\n");
                return 1;
            }

            printf("Network Interfaces:\n\n");
            for (int i = 0; i < count; i++) {
                print_interface_stats(&stats[i]);
                printf("\n");
            }

            free_interface_stats(stats, count);
            break;
        }

        case CMD_SHOW_STATS: {
            interface_stats_t stats;

            if (get_interface_stats(args.interface, &stats) < 0) {
                fprintf(stderr, "Failed to get interface statistics\n");
                return 1;
            }

            strncpy(stats.name, args.interface, 255);
            print_interface_stats(&stats);
            break;
        }

        case CMD_CAPTURE:
            if (start_capture(args.interface, args.filter, args.packet_count, args.promisc) < 0) {
                return 1;
            }
            break;

        case CMD_TCP_STRESS: {
            stress_config_t config;
            stress_result_t result;

            config.host = args.host;
            config.port = args.port;
            config.concurrency = args.concurrency;
            config.duration_sec = args.duration;
            config.rate_limit = args.rate_limit;
            config.is_http = 0;
            config.http_path = NULL;

            if (run_tcp_stress(&config, &result) < 0) {
                return 1;
            }

            if (args.json_output) {
                print_stress_json(&result);
            } else {
                print_stress_results(&result);
            }
            break;
        }

        case CMD_HTTP_STRESS: {
            stress_config_t config;
            stress_result_t result;

            config.host = args.host;
            config.port = args.port;
            config.concurrency = args.concurrency;
            config.duration_sec = args.duration;
            config.rate_limit = args.rate_limit;
            config.is_http = 1;
            config.http_path = strlen(args.http_path) > 0 ? args.http_path : "/";

            if (run_http_stress(&config, &result) < 0) {
                return 1;
            }

            if (args.json_output) {
                print_stress_json(&result);
            } else {
                print_stress_results(&result);
            }
            break;
        }

        case CMD_PACKET_FLOOD:
            if (packet_flood(args.interface, args.host, args.port, args.duration, args.rate_limit) < 0) {
                return 1;
            }
            break;

        case CMD_PORT_SCAN:
            if (scan_ports(args.host, args.start_port, args.end_port, args.timeout) < 0) {
                return 1;
            }
            break;

        case CMD_VULN_SCAN:
            if (detect_vulnerabilities(args.host, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_SCAN_PROCESSES:
            if (scan_network_processes(args.process_filter, args.pid_filter) < 0) {
                return 1;
            }
            break;

        default:
            fprintf(stderr, "Unknown command\n");
            return 1;
    }

    return 0;
}