#include "ripnet/cli.h"
#include "ripnet/stats.h"
#include "ripnet/packet.h"
#include "ripnet/stress.h"
#include "ripnet/process.h"
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

        case CMD_DNS_LOOKUP: {
            dns_lookup_result_t dns_result;
            if (dns_lookup(args.hostname, &dns_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_DNS_REVERSE: {
            char hostname[256];
            if (dns_reverse_lookup(args.ip_address, hostname, sizeof(hostname)) < 0) {
                return 1;
            }
            break;
        }

        case CMD_DNS_QUERY: {
            char result[512];
            if (dns_query(args.hostname, args.record_type, result, sizeof(result)) < 0) {
                return 1;
            }
            break;
        }

        case CMD_DNS_SERVER_TEST: {
            dns_server_test_result_t dns_result;
            if (dns_server_test(args.dns_server, &dns_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_DNS_TRACE:
            if (dns_trace(args.hostname) < 0) {
                return 1;
            }
            break;

        case CMD_DNS_CACHE_FLUSH:
            if (dns_cache_flush() < 0) {
                return 1;
            }
            break;

        case CMD_TRACEROUTE: {
            traceroute_result_t trace_result;
            if (traceroute(args.hostname, &trace_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_TRACEROUTE_TCP: {
            traceroute_result_t trace_result;
            if (traceroute_tcp(args.hostname, args.port, &trace_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_TRACEROUTE_UDP: {
            traceroute_result_t trace_result;
            if (traceroute_udp(args.hostname, &trace_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_PING: {
            ping_result_t ping_result;
            if (ping(args.hostname, args.count, &ping_result) < 0) {
                return 1;
            }
            print_ping_results(&ping_result);
            break;
        }

        case CMD_PING_TCP: {
            ping_result_t ping_result;
            if (ping_tcp(args.hostname, args.port, &ping_result) < 0) {
                return 1;
            }
            print_ping_results(&ping_result);
            break;
        }

        case CMD_SCAN: {
            scan_result_t scan_result;
            if (port_scan(args.host, args.start_port, args.end_port, &scan_result) < 0) {
                return 1;
            }
            print_scan_results(&scan_result);
            break;
        }

        case CMD_SERVICE_SCAN: {
            char service[256];
            if (service_scan(args.hostname, args.port, service, sizeof(service)) < 0) {
                return 1;
            }
            break;
        }

        case CMD_OS_FINGERPRINT: {
            char os[256];
            if (os_fingerprint(args.hostname, os, sizeof(os)) < 0) {
                return 1;
            }
            break;
        }

        case CMD_NETSTAT: {
            netstat_result_t netstat_result;
            if (netstat_connections(&netstat_result) < 0) {
                return 1;
            }
            print_netstat_results(&netstat_result);
            break;
        }

        case CMD_NETSTAT_LISTENING: {
            netstat_result_t netstat_result;
            if (netstat_listening(&netstat_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_NETSTAT_ROUTE:
            if (netstat_route() < 0) {
                return 1;
            }
            break;

        case CMD_ARP_TABLE: {
            arp_table_t arp_tbl;
            if (arp_table(&arp_tbl) < 0) {
                return 1;
            }
            break;
        }

        case CMD_ARP_SCAN: {
            arp_table_t arp_tbl;
            if (arp_scan(args.domain, &arp_tbl) < 0) {
                return 1;
            }
            break;
        }

        case CMD_ARP_FLUSH:
            if (arp_flush(args.interface) < 0) {
                return 1;
            }
            break;

        case CMD_ROUTE_TABLE: {
            route_table_t route_tbl;
            if (route_table(&route_tbl) < 0) {
                return 1;
            }
            break;
        }

        case CMD_ROUTE_ADD:
            if (route_add(args.host, args.gateway, args.netmask, args.interface) < 0) {
                return 1;
            }
            break;

        case CMD_ROUTE_DELETE:
            if (route_delete(args.host) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_LIST: {
            firewall_ruleset_t ruleset;
            if (firewall_list(&ruleset) < 0) {
                return 1;
            }
            break;
        }

        case CMD_FIREWALL_ADD:
            if (firewall_add(args.chain, args.rule) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_DELETE:
            if (firewall_delete(args.chain, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_FLUSH:
            if (firewall_flush(args.chain) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_BLOCK_IP:
            if (firewall_block_ip(args.ip_address) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_UNBLOCK_IP:
            if (firewall_unblock_ip(args.ip_address) < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_BLOCK_PORT:
            if (firewall_block_port(args.port, "tcp") < 0) {
                return 1;
            }
            break;

        case CMD_FIREWALL_UNBLOCK_PORT:
            if (firewall_unblock_port(args.port, "tcp") < 0) {
                return 1;
            }
            break;

        case CMD_BANDWIDTH_TEST: {
            bandwidth_result_t bw_result;
            if (bandwidth_test(args.interface, &bw_result) < 0) {
                return 1;
            }
            print_bandwidth_results(&bw_result);
            break;
        }

        case CMD_BANDWIDTH_MONITOR:
            if (bandwidth_monitor(args.interface, args.interval) < 0) {
                return 1;
            }
            break;

        case CMD_MONITOR_START:
            if (monitor_start(args.interface) < 0) {
                return 1;
            }
            break;

        case CMD_MONITOR_ALERT:
            if (monitor_alert(args.interface, args.threshold) < 0) {
                return 1;
            }
            break;

        case CMD_DISCOVERY_PING: {
            discovery_result_t disc_result;
            if (discovery_ping(args.domain, &disc_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_DISCOVERY_ARP: {
            discovery_result_t disc_result;
            if (discovery_arp(args.domain, &disc_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_SECURITY_SCAN: {
            security_scan_result_t sec_result;
            if (security_scan(args.hostname, &sec_result) < 0) {
                return 1;
            }
            break;
        }

        case CMD_SECURITY_AUDIT:
            if (security_audit(args.hostname) < 0) {
                return 1;
            }
            break;

        case CMD_SECURITY_SSL:
            if (security_ssl_check(args.hostname, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_SECURITY_SSH:
            if (security_ssh_check(args.hostname, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_SECURITY_HTTP:
            if (security_http_check(args.hostname, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_SECURITY_SMTP:
            if (security_smtp_check(args.hostname, args.port) < 0) {
                return 1;
            }
            break;

        case CMD_SECURITY_BANNER: {
            char banner[512];
            if (security_banner_grab(args.hostname, args.port, banner, sizeof(banner)) < 0) {
                return 1;
            }
            break;
        }

        default:
            fprintf(stderr, "Unknown command\n");
            return 1;
    }

    return 0;
}