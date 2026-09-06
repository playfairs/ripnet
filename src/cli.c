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
#if defined(__has_include)
#if __has_include("ripnet_version.h")
#include "ripnet_version.h"
#else
#define RIPNET_VERSION "unknown"
#endif
#else
#define RIPNET_VERSION "unknown"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

enum {
    OPT_DNS_SERVER_TEST = 1000,
    OPT_DNS_BRUTEFORCE,
    OPT_DNS_ZONE_TRANSFER,
    OPT_DNSSEC_VERIFY,
    OPT_TRACEROUTE_ICMP,
    OPT_PING_UDP,
    OPT_PING_SWEEP,
    OPT_PING_FLOOD,
    OPT_NETWORK_SCAN,
    OPT_UDP_SCAN,
    OPT_SYN_SCAN,
    OPT_FIN_SCAN,
    OPT_XMAS_SCAN,
    OPT_NULL_SCAN,
    OPT_NETSTAT_PROCESS,
    OPT_NETSTAT_INTERFACE,
    OPT_NETSTAT_GROUP,
    OPT_NETSTAT_TIMER,
    OPT_ROUTE_GET,
    OPT_ROUTE_TRACE,
    OPT_ROUTE_MONITOR,
    OPT_ARP_SPOOF_DETECT,
    OPT_ARP_REQUEST,
    OPT_ARP_REPLY,
    OPT_ARP_CACHE_ADD,
    OPT_ARP_CACHE_DELETE,
    OPT_FIREWALL_STATUS,
    OPT_FIREWALL_LOG,
    OPT_BANDWIDTH_SPEEDTEST,
    OPT_BANDWIDTH_HISTORY,
    OPT_BANDWIDTH_LIMIT,
    OPT_BANDWIDTH_SHAPER,
    OPT_MONITOR_STOP,
    OPT_MONITOR_STATUS,
    OPT_MONITOR_LOG,
    OPT_MONITOR_EXPORT,
    OPT_DISCOVERY_DNS,
    OPT_DISCOVERY_SNMP,
    OPT_DISCOVERY_UPNP,
    OPT_DISCOVERY_MDNS,
    OPT_DISCOVERY_LLMNR,
    OPT_DISCOVERY_NETBIOS,
    OPT_DISCOVERY_SMB,
    OPT_DISCOVERY_HTTP,
    OPT_DISCOVERY_SSL,
    OPT_SECURITY_DNS,
    OPT_SECURITY_MITM_DETECT,
    OPT_SECURITY_PORT_KNOCKING,
    OPT_SECURITY_HONEYPOT_DETECT,
    OPT_MAX_BPS,
    OPT_DOWNLOAD_BPS,
    OPT_UPLOAD_BPS,
    OPT_MAC_ADDRESS,
    OPT_LOG_PATH,
    OPT_EXPORT_PATH,
    OPT_WORDLIST,
    OPT_INTERFACE,
    OPT_PORTS,
    OPT_RECORD_TYPE,
    OPT_PROTOCOL
};

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
    {"dns-server-test", required_argument, 0, OPT_DNS_SERVER_TEST},
    {"dns-bruteforce", required_argument, 0, OPT_DNS_BRUTEFORCE},
    {"dns-zone-transfer", required_argument, 0, OPT_DNS_ZONE_TRANSFER},
    {"dnssec-verify", required_argument, 0, OPT_DNSSEC_VERIFY},
    {"traceroute-icmp", required_argument, 0, OPT_TRACEROUTE_ICMP},
    {"ping-udp", required_argument, 0, OPT_PING_UDP},
    {"ping-sweep", required_argument, 0, OPT_PING_SWEEP},
    {"ping-flood", required_argument, 0, OPT_PING_FLOOD},
    {"network-scan", required_argument, 0, OPT_NETWORK_SCAN},
    {"udp-scan", required_argument, 0, OPT_UDP_SCAN},
    {"syn-scan", required_argument, 0, OPT_SYN_SCAN},
    {"fin-scan", required_argument, 0, OPT_FIN_SCAN},
    {"xmas-scan", required_argument, 0, OPT_XMAS_SCAN},
    {"null-scan", required_argument, 0, OPT_NULL_SCAN},
    {"netstat-process", required_argument, 0, OPT_NETSTAT_PROCESS},
    {"netstat-interface", required_argument, 0, OPT_NETSTAT_INTERFACE},
    {"netstat-group", required_argument, 0, OPT_NETSTAT_GROUP},
    {"netstat-timer", no_argument, 0, OPT_NETSTAT_TIMER},
    {"route-get", required_argument, 0, OPT_ROUTE_GET},
    {"route-trace", required_argument, 0, OPT_ROUTE_TRACE},
    {"route-monitor", no_argument, 0, OPT_ROUTE_MONITOR},
    {"arp-spoof-detect", required_argument, 0, OPT_ARP_SPOOF_DETECT},
    {"arp-request", required_argument, 0, OPT_ARP_REQUEST},
    {"arp-reply", required_argument, 0, OPT_ARP_REPLY},
    {"arp-cache-add", required_argument, 0, OPT_ARP_CACHE_ADD},
    {"arp-cache-delete", required_argument, 0, OPT_ARP_CACHE_DELETE},
    {"firewall-status", no_argument, 0, OPT_FIREWALL_STATUS},
    {"firewall-log", required_argument, 0, OPT_FIREWALL_LOG},
    {"bandwidth-speedtest", required_argument, 0, OPT_BANDWIDTH_SPEEDTEST},
    {"bandwidth-history", required_argument, 0, OPT_BANDWIDTH_HISTORY},
    {"bandwidth-limit", required_argument, 0, OPT_BANDWIDTH_LIMIT},
    {"bandwidth-shaper", required_argument, 0, OPT_BANDWIDTH_SHAPER},
    {"monitor-stop", no_argument, 0, OPT_MONITOR_STOP},
    {"monitor-status", no_argument, 0, OPT_MONITOR_STATUS},
    {"monitor-log", required_argument, 0, OPT_MONITOR_LOG},
    {"monitor-export", required_argument, 0, OPT_MONITOR_EXPORT},
    {"discovery-dns", required_argument, 0, OPT_DISCOVERY_DNS},
    {"discovery-snmp", required_argument, 0, OPT_DISCOVERY_SNMP},
    {"discovery-upnp", required_argument, 0, OPT_DISCOVERY_UPNP},
    {"discovery-mdns", required_argument, 0, OPT_DISCOVERY_MDNS},
    {"discovery-llmnr", required_argument, 0, OPT_DISCOVERY_LLMNR},
    {"discovery-netbios", required_argument, 0, OPT_DISCOVERY_NETBIOS},
    {"discovery-smb", required_argument, 0, OPT_DISCOVERY_SMB},
    {"discovery-http", required_argument, 0, OPT_DISCOVERY_HTTP},
    {"discovery-ssl", required_argument, 0, OPT_DISCOVERY_SSL},
    {"security-dns", required_argument, 0, OPT_SECURITY_DNS},
    {"security-mitm-detect", required_argument, 0, OPT_SECURITY_MITM_DETECT},
    {"security-port-knocking", required_argument, 0, OPT_SECURITY_PORT_KNOCKING},
    {"security-honeypot-detect", required_argument, 0, OPT_SECURITY_HONEYPOT_DETECT},
    {"max-bps", required_argument, 0, OPT_MAX_BPS},
    {"download-bps", required_argument, 0, OPT_DOWNLOAD_BPS},
    {"upload-bps", required_argument, 0, OPT_UPLOAD_BPS},
    {"mac-address", required_argument, 0, OPT_MAC_ADDRESS},
    {"log-path", required_argument, 0, OPT_LOG_PATH},
    {"export-path", required_argument, 0, OPT_EXPORT_PATH},
    {"wordlist", required_argument, 0, OPT_WORDLIST},
    {"interface", required_argument, 0, OPT_INTERFACE},
    {"ports", required_argument, 0, OPT_PORTS},
    {"record-type", required_argument, 0, OPT_RECORD_TYPE},
    {"protocol", required_argument, 0, OPT_PROTOCOL},
    {"json", no_argument, 0, 'j'},
    {"verbose", no_argument, 0, 'v'},
    {"help", no_argument, 0, '?'},
    {"version", no_argument, 0, 'w'},
    {0, 0, 0, 0}
};

void print_usage(void)
{
    printf("ripnet - network diagnostics and analysis toolkit\n\n");
    printf("Usage:\n");
    printf("  ripnet [OPTIONS]\n\n");
    printf("Common commands:\n");
    printf("  ripnet --list-interfaces\n");
    printf("  ripnet --show-stats IFACE\n");
    printf("  ripnet --ping HOST --ping-count N\n");
    printf("  ripnet --dns-lookup HOST\n");
    printf("  ripnet --scan HOST --start-port PORT --end-port PORT\n\n");
    printf("Run 'ripnet --help' for the full manual.\n");
}

void print_help(void)
{
    printf("RIPNET(1)                 User Commands                RIPNET(1)\n\n");
    printf("NAME\n");
    printf("  ripnet - advanced network diagnostics, security, and analysis toolkit\n\n");
    printf("SYNOPSIS\n");
    printf("  ripnet [OPTIONS]\n\n");
    printf("DESCRIPTION\n");
    printf("  ripnet provides interface inspection, packet capture, DNS tools,\n");
    printf("  tracing, ping, scanning, route and firewall helpers, bandwidth\n");
    printf("  monitoring, discovery, and authorized security checks from one CLI.\n\n");
    printf("OPTIONS\n");
    printf("  Interface Discovery:\n");
    printf("  -l, --list-interfaces          List all network interfaces\n");
    printf("  -s, --show-stats IFACE         Show statistics for interface\n\n");
    printf("  Packet Capture:\n");
    printf("  -c, --capture IFACE            Start packet capture on interface\n");
    printf("  -f, --filter FILTER            BPF filter expression\n");
    printf("  -n, --count N                  Capture N packets then exit\n");
    printf("  -p, --promisc                  Enable promiscuous mode\n\n");
    printf("  Load Testing:\n");
    printf("  -t, --tcp-stress HOST          Run TCP stress test\n");
    printf("  -h, --http-stress HOST         Run HTTP stress test\n");
    printf("  -P, --port PORT                Target port\n");
    printf("  -C, --concurrency N            Number of concurrent connections\n");
    printf("  -D, --duration SECONDS         Test duration\n");
    printf("  -R, --rate-limit N             Rate limit (connections/sec)\n");
    printf("  -H, --http-path PATH           HTTP path for stress test\n\n");
    printf("  DNS Tools:\n");
    printf("  -d, --dns-lookup HOST          DNS lookup\n");
    printf("  -r, --dns-reverse IP           Reverse DNS lookup\n");
    printf("  -q, --dns-query HOST TYPE     DNS query (A, AAAA, MX, etc.)\n");
    printf("  -Z, --dns-server SERVER        DNS server for queries\n");
    printf("  -Y, --dns-trace HOST           DNS trace\n");
    printf("  -Q, --dns-cache-flush          Flush DNS cache\n\n");
    printf("  Network Tracing:\n");
    printf("  -g, --traceroute HOST          Traceroute to host\n");
    printf("  -G, --traceroute-tcp HOST     TCP traceroute\n");
    printf("  -U, --traceroute-udp HOST     UDP traceroute\n\n");
    printf("  Ping Tools:\n");
    printf("  -i, --ping HOST                Ping host\n");
    printf("  -J, --ping-tcp HOST:PORT       TCP ping\n");
    printf("  -K, --ping-count N             Number of pings\n\n");
    printf("  Scanning:\n");
    printf("  -M, --scan HOST                Port scan\n");
    printf("  -O, --service-scan HOST:PORT   Service scan\n");
    printf("  -B, --os-fingerprint HOST       OS fingerprinting\n");
    printf("  -a, --start-port PORT         Start port for scan\n");
    printf("  -e, --end-port PORT           End port for scan\n");
    printf("  -T, --timeout MS               Connection timeout\n\n");
    printf("  Network Statistics:\n");
    printf("  -E, --netstat                  Show network connections\n");
    printf("  -L, --netstat-listening        Show listening ports\n");
    printf("  -W, --netstat-route            Show routing table\n\n");
    printf("  ARP Tools:\n");
    printf("  -A, --arp-table                Show ARP table\n");
    printf("  -y, --arp-scan NETWORK         ARP scan network\n");
    printf("  -z, --arp-flush IFACE          Flush ARP cache\n\n");
    printf("  Routing:\n");
    printf("  -o, --route-table              Show routing table\n");
    printf("  -1, --route-add DEST           Add route\n");
    printf("  -2, --route-delete DEST        Delete route\n");
    printf("  -3, --gateway GATEWAY          Gateway for route\n");
    printf("  -4, --netmask NETMASK          Netmask for route\n\n");
    printf("  Firewall:\n");
    printf("  -5, --firewall-list            List firewall rules\n");
    printf("  -6, --firewall-add RULE        Add firewall rule\n");
    printf("  -7, --firewall-delete RULE     Delete firewall rule\n");
    printf("  -8, --firewall-flush CHAIN     Flush firewall chain\n");
    printf("  -9, --chain CHAIN              Firewall chain\n");
    printf("  --block-ip IP                  Block IP address\n");
    printf("  --unblock-ip IP                Unblock IP address\n");
    printf("  --block-port PORT PROTO        Block port\n");
    printf("  --unblock-port PORT PROTO      Unblock port\n\n");
    printf("  Bandwidth:\n");
    printf("  --bandwidth-test IFACE         Test bandwidth\n");
    printf("  --bandwidth-monitor IFACE      Monitor bandwidth\n\n");
    printf("  Monitoring:\n");
    printf("  --monitor-start IFACE          Start network monitor\n");
    printf("  --monitor-alert IFACE          Monitor with alerts\n");
    printf("  --threshold MBPS              Alert threshold\n\n");
    printf("  Discovery:\n");
    printf("  --discovery-ping NETWORK       Ping discovery\n");
    printf("  --discovery-arp NETWORK       ARP discovery\n\n");
    printf("  Security:\n");
    printf("  --security-scan HOST           Security scan\n");
    printf("  --security-audit HOST          Security audit\n");
    printf("  --security-ssl HOST:PORT       SSL security check\n");
    printf("  --security-ssh HOST:PORT       SSH security check\n");
    printf("  --security-http HOST:PORT      HTTP security check\n");
    printf("  --security-smtp HOST:PORT      SMTP security check\n");
    printf("  --security-banner HOST:PORT    Banner grab\n\n");
    printf("  Extended DNS and Tracing:\n");
    printf("  --dns-server-test SERVER       Test a DNS server\n");
    printf("  --dns-bruteforce DOMAIN       Brute-force DNS names from --wordlist\n");
    printf("  --dns-zone-transfer DOMAIN     Attempt an authorized zone transfer\n");
    printf("  --dnssec-verify DOMAIN         Verify DNSSEC\n");
    printf("  --record-type TYPE             DNS record type for --dns-query\n");
    printf("  --protocol PROTOCOL            Protocol for firewall port operations\n");
    printf("  --traceroute-icmp HOST         ICMP traceroute\n");
    printf("  --ping-udp HOST                UDP ping\n");
    printf("  --ping-sweep NETWORK            Sweep a network with ICMP\n");
    printf("  --ping-flood HOST              Authorized ping flood test\n\n");
    printf("  Scan Modes:\n");
    printf("  --network-scan NETWORK         Scan hosts on a network\n");
    printf("  --udp-scan HOST                UDP port scan\n");
    printf("  --syn-scan HOST                TCP SYN scan\n");
    printf("  --fin-scan HOST                TCP FIN scan\n");
    printf("  --xmas-scan HOST               TCP XMAS scan\n");
    printf("  --null-scan HOST               TCP NULL scan\n");
    printf("  --start-port PORT              First port\n");
    printf("  --end-port PORT                Last port\n\n");
    printf("  Extended System and Network Tools:\n");
    printf("  --netstat-process PID          Connections owned by a process\n");
    printf("  --netstat-interface IFACE      Interface network statistics\n");
    printf("  --netstat-group GROUP          Group network statistics\n");
    printf("  --netstat-timer                Network timer statistics\n");
    printf("  --route-get DEST               Resolve a route\n");
    printf("  --route-trace DEST             Trace route changes\n");
    printf("  --route-monitor                Monitor route changes\n");
    printf("  --arp-spoof-detect IFACE       Detect ARP spoofing\n");
    printf("  --arp-request IP               Send an ARP request\n");
    printf("  --arp-reply IP                 Send an ARP reply\n");
    printf("  --arp-cache-add IP             Add an ARP cache entry\n");
    printf("  --arp-cache-delete IP          Delete an ARP cache entry\n");
    printf("  --interface IFACE              Shared interface parameter\n");
    printf("  --mac-address MAC              Shared MAC parameter\n\n");
    printf("  Extended Performance and Discovery:\n");
    printf("  --firewall-status              Show firewall status\n");
    printf("  --firewall-log 0|1             Disable or enable firewall logging\n");
    printf("  --bandwidth-speedtest SERVER   Run a bandwidth speed test\n");
    printf("  --bandwidth-history IFACE      Show bandwidth history\n");
    printf("  --bandwidth-limit IFACE        Apply a bandwidth limit\n");
    printf("  --bandwidth-shaper IFACE       Configure bandwidth shaping\n");
    printf("  --max-bps RATE                 Maximum rate for bandwidth limit\n");
    printf("  --download-bps RATE            Download shaping rate\n");
    printf("  --upload-bps RATE              Upload shaping rate\n");
    printf("  --monitor-stop                 Stop monitoring\n");
    printf("  --monitor-status               Show monitor status\n");
    printf("  --monitor-log IFACE            Log interface monitoring\n");
    printf("  --monitor-export IFACE         Export interface monitoring\n");
    printf("  --discovery-dns DOMAIN         Discover DNS hosts\n");
    printf("  --discovery-snmp NETWORK       Discover SNMP hosts\n");
    printf("  --discovery-upnp NETWORK       Discover UPnP devices\n");
    printf("  --discovery-mdns NETWORK       Discover mDNS services\n");
    printf("  --discovery-llmnr NETWORK      Discover LLMNR hosts\n");
    printf("  --discovery-netbios NETWORK    Discover NetBIOS hosts\n");
    printf("  --discovery-smb NETWORK        Discover SMB hosts\n");
    printf("  --discovery-http NETWORK       Discover HTTP hosts\n");
    printf("  --discovery-ssl NETWORK        Discover SSL hosts\n\n");
    printf("  Extended Security:\n");
    printf("  --security-dns SERVER          Check DNS security\n");
    printf("  --security-mitm-detect IFACE   Detect possible MITM activity\n");
    printf("  --security-port-knocking HOST  Run an authorized port-knocking test\n");
    printf("  --security-honeypot-detect HOST Detect honeypot indicators\n");
    printf("  --ports LIST                   Comma-separated ports for knocking\n");
    printf("  --wordlist FILE                Wordlist for DNS brute force\n\n");
    printf("  Process Scanning:\n");
    printf("  -N, --scan-processes           Scan network processes\n");
    printf("  -X, --process NAME             Filter by process name\n");
    printf("  -I, --pid PID                  Filter by PID\n\n");
    printf("  Output:\n");
    printf("  -j, --json                     Output in JSON format\n");
    printf("  -v, --verbose                  Verbose output\n");
    printf("  -?, --help                     Show this manual page\n");
    printf("  -w, --version                  Show version information\n\n");
    printf("EXAMPLES\n");
    printf("  ripnet --list-interfaces\n");
    printf("  ripnet --dns-lookup example.com\n");
    printf("  ripnet --traceroute example.com\n");
    printf("  ripnet --ping example.com --ping-count 5\n");
    printf("  ripnet --scan 192.168.1.1 --start-port 1 --end-port 1000\n");
    printf("  ripnet --arp-table\n");
    printf("  ripnet --firewall-list\n");
    printf("  ripnet --bandwidth-test eth0\n");
    printf("  ripnet --security-ssh example.com:22\n");
    printf("\nEXIT STATUS\n");
    printf("  0  Command completed successfully.\n");
    printf("  1  Command failed, arguments were invalid, or required resources were unavailable.\n\n");
    printf("RIPNET(1)                 User Commands                RIPNET(1)\n");
}

void print_version(void)
{
    printf("ripnet version %s\n", RIPNET_VERSION);
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
    strncpy(args->protocol, "tcp", sizeof(args->protocol) - 1);

    while ((opt = getopt_long(argc, argv, "ls:c:f:n:pt:h:P:C:D:R:H:F:S:a:e:T:V:NX:I:jv?d:r:q:Z:Y:Qg:G:Ui:J:K:M:O:B:ELWA:y:z:o:1:2:3:4:5:6:7:8:9:!:@:#:$:%:^:&:*():_:+:-:=:[:]:{:}w", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l':
                args->cmd = CMD_LIST_INTERFACES;
                break;
            case 's':
                args->cmd = CMD_SHOW_STATS;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case 'c':
                args->cmd = CMD_CAPTURE;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case 'f':
                strncpy(args->filter, optarg, sizeof(args->filter) - 1);
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
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case 'h':
                args->cmd = CMD_HTTP_STRESS;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
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
                strncpy(args->http_path, optarg, sizeof(args->http_path) - 1);
                break;
            case 'F':
                args->cmd = CMD_PACKET_FLOOD;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case 'S':
                args->cmd = CMD_PORT_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
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
                strncpy(args->process_filter, optarg, sizeof(args->process_filter) - 1);
                break;
            case 'I':
                if (parse_uint(optarg, (unsigned int *)&args->pid_filter) < 0) {
                    fprintf(stderr, "Invalid PID: %s\n", optarg);
                    return -1;
                }
                break;
            case 'd':
                args->cmd = CMD_DNS_LOOKUP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'r':
                args->cmd = CMD_DNS_REVERSE;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case 'q':
                args->cmd = CMD_DNS_QUERY;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'Z':
                strncpy(args->dns_server, optarg, sizeof(args->dns_server) - 1);
                break;
            case 'Y':
                args->cmd = CMD_DNS_TRACE;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'Q':
                args->cmd = CMD_DNS_CACHE_FLUSH;
                break;
            case 'g':
                args->cmd = CMD_TRACEROUTE;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'G':
                args->cmd = CMD_TRACEROUTE_TCP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'U':
                args->cmd = CMD_TRACEROUTE_UDP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'i':
                args->cmd = CMD_PING;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'J':
                args->cmd = CMD_PING_TCP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'K':
                if (parse_uint(optarg, (unsigned int *)&args->count) < 0) {
                    fprintf(stderr, "Invalid ping count: %s\n", optarg);
                    return -1;
                }
                break;
            case 'M':
                args->cmd = CMD_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case 'O':
                args->cmd = CMD_SERVICE_SCAN;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case 'B':
                args->cmd = CMD_OS_FINGERPRINT;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
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
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case 'z':
                args->cmd = CMD_ARP_FLUSH;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case 'o':
                args->cmd = CMD_ROUTE_TABLE;
                break;
            case '1':
                args->cmd = CMD_ROUTE_ADD;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case '2':
                args->cmd = CMD_ROUTE_DELETE;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case '3':
                strncpy(args->gateway, optarg, sizeof(args->gateway) - 1);
                break;
            case '4':
                strncpy(args->netmask, optarg, sizeof(args->netmask) - 1);
                break;
            case '5':
                args->cmd = CMD_FIREWALL_LIST;
                break;
            case '6':
                args->cmd = CMD_FIREWALL_ADD;
                strncpy(args->rule, optarg, sizeof(args->rule) - 1);
                break;
            case '7':
                args->cmd = CMD_FIREWALL_DELETE;
                if (parse_uint(optarg, (unsigned int *)&args->port) < 0) {
                    fprintf(stderr, "Invalid firewall rule number: %s\n", optarg);
                    return -1;
                }
                break;
            case '8':
                args->cmd = CMD_FIREWALL_FLUSH;
                strncpy(args->chain, optarg, sizeof(args->chain) - 1);
                break;
            case '9':
                strncpy(args->chain, optarg, sizeof(args->chain) - 1);
                break;
            case '!':
                args->cmd = CMD_FIREWALL_BLOCK_IP;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case '@':
                args->cmd = CMD_FIREWALL_UNBLOCK_IP;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
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
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case '^':
                args->cmd = CMD_BANDWIDTH_MONITOR;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case '&':
                args->cmd = CMD_MONITOR_START;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case '*':
                args->cmd = CMD_MONITOR_ALERT;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case '(':
                args->threshold = atof(optarg);
                break;
            case ')':
                args->cmd = CMD_DISCOVERY_PING;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case '_':
                args->cmd = CMD_DISCOVERY_ARP;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case '+':
                args->cmd = CMD_SECURITY_SCAN;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case '-':
                args->cmd = CMD_SECURITY_AUDIT;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case '=':
                args->cmd = CMD_SECURITY_SSL;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case '[':
                args->cmd = CMD_SECURITY_SSH;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case ']':
                args->cmd = CMD_SECURITY_HTTP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case '{':
                args->cmd = CMD_SECURITY_SMTP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case '}':
                args->cmd = CMD_SECURITY_BANNER;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case OPT_DNS_SERVER_TEST:
                args->cmd = CMD_DNS_SERVER_TEST;
                strncpy(args->dns_server, optarg, sizeof(args->dns_server) - 1);
                break;
            case OPT_DNS_BRUTEFORCE:
                args->cmd = CMD_DNS_BRUTEFORCE;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DNS_ZONE_TRANSFER:
                args->cmd = CMD_DNS_ZONE_TRANSFER;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DNSSEC_VERIFY:
                args->cmd = CMD_DNSSEC_VERIFY;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_TRACEROUTE_ICMP:
                args->cmd = CMD_TRACEROUTE_ICMP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case OPT_PING_UDP:
                args->cmd = CMD_PING_UDP;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case OPT_PING_SWEEP:
                args->cmd = CMD_PING_SWEEP;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_PING_FLOOD:
                args->cmd = CMD_PING_FLOOD;
                strncpy(args->hostname, optarg, sizeof(args->hostname) - 1);
                break;
            case OPT_NETWORK_SCAN:
                args->cmd = CMD_NETWORK_SCAN;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_UDP_SCAN:
                args->cmd = CMD_UDP_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_SYN_SCAN:
                args->cmd = CMD_SYN_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_FIN_SCAN:
                args->cmd = CMD_FIN_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_XMAS_SCAN:
                args->cmd = CMD_XMAS_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_NULL_SCAN:
                args->cmd = CMD_NULL_SCAN;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_NETSTAT_PROCESS:
                args->cmd = CMD_NETSTAT_PROCESS;
                if (parse_uint(optarg, (unsigned int *)&args->pid_filter) < 0) {
                    fprintf(stderr, "Invalid PID: %s\n", optarg);
                    return -1;
                }
                break;
            case OPT_NETSTAT_INTERFACE:
                args->cmd = CMD_NETSTAT_INTERFACE;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_NETSTAT_GROUP:
                args->cmd = CMD_NETSTAT_GROUP;
                strncpy(args->rule, optarg, sizeof(args->rule) - 1);
                break;
            case OPT_NETSTAT_TIMER:
                args->cmd = CMD_NETSTAT_TIMER;
                break;
            case OPT_ROUTE_GET:
                args->cmd = CMD_ROUTE_GET;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_ROUTE_TRACE:
                args->cmd = CMD_ROUTE_TRACE;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_ROUTE_MONITOR:
                args->cmd = CMD_ROUTE_MONITOR;
                break;
            case OPT_ARP_SPOOF_DETECT:
                args->cmd = CMD_ARP_SPOOF_DETECT;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_ARP_REQUEST:
                args->cmd = CMD_ARP_REQUEST;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case OPT_ARP_REPLY:
                args->cmd = CMD_ARP_REPLY;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case OPT_ARP_CACHE_ADD:
                args->cmd = CMD_ARP_CACHE_ADD;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case OPT_ARP_CACHE_DELETE:
                args->cmd = CMD_ARP_CACHE_DELETE;
                strncpy(args->ip_address, optarg, sizeof(args->ip_address) - 1);
                break;
            case OPT_FIREWALL_STATUS:
                args->cmd = CMD_FIREWALL_STATUS;
                break;
            case OPT_FIREWALL_LOG:
                args->cmd = CMD_FIREWALL_LOG;
                if (parse_uint(optarg, (unsigned int *)&args->count) < 0 || args->count > 1) {
                    fprintf(stderr, "Firewall logging expects 0 or 1\n");
                    return -1;
                }
                break;
            case OPT_BANDWIDTH_SPEEDTEST:
                args->cmd = CMD_BANDWIDTH_SPEEDTEST;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_BANDWIDTH_HISTORY:
                args->cmd = CMD_BANDWIDTH_HISTORY;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_BANDWIDTH_LIMIT:
                args->cmd = CMD_BANDWIDTH_LIMIT;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_BANDWIDTH_SHAPER:
                args->cmd = CMD_BANDWIDTH_SHAPER;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_MONITOR_STOP:
                args->cmd = CMD_MONITOR_STOP;
                break;
            case OPT_MONITOR_STATUS:
                args->cmd = CMD_MONITOR_STATUS;
                break;
            case OPT_MONITOR_LOG:
                args->cmd = CMD_MONITOR_LOG;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_MONITOR_EXPORT:
                args->cmd = CMD_MONITOR_EXPORT;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_DISCOVERY_DNS:
                args->cmd = CMD_DISCOVERY_DNS;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_SNMP:
                args->cmd = CMD_DISCOVERY_SNMP;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_UPNP:
                args->cmd = CMD_DISCOVERY_UPNP;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_MDNS:
                args->cmd = CMD_DISCOVERY_MDNS;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_LLMNR:
                args->cmd = CMD_DISCOVERY_LLMNR;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_NETBIOS:
                args->cmd = CMD_DISCOVERY_NETBIOS;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_SMB:
                args->cmd = CMD_DISCOVERY_SMB;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_HTTP:
                args->cmd = CMD_DISCOVERY_HTTP;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_DISCOVERY_SSL:
                args->cmd = CMD_DISCOVERY_SSL;
                strncpy(args->domain, optarg, sizeof(args->domain) - 1);
                break;
            case OPT_SECURITY_DNS:
                args->cmd = CMD_SECURITY_DNS;
                strncpy(args->dns_server, optarg, sizeof(args->dns_server) - 1);
                break;
            case OPT_SECURITY_MITM_DETECT:
                args->cmd = CMD_SECURITY_MITM_DETECT;
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_SECURITY_PORT_KNOCKING:
                args->cmd = CMD_SECURITY_PORT_KNOCKING;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_SECURITY_HONEYPOT_DETECT:
                args->cmd = CMD_SECURITY_HONEYPOT_DETECT;
                strncpy(args->host, optarg, sizeof(args->host) - 1);
                break;
            case OPT_MAX_BPS: {
                unsigned long value;
                if (parse_ulong(optarg, &value) < 0) {
                    fprintf(stderr, "Invalid maximum rate: %s\n", optarg);
                    return -1;
                }
                args->max_bps = value;
                break;
            }
            case OPT_DOWNLOAD_BPS: {
                unsigned long value;
                if (parse_ulong(optarg, &value) < 0) {
                    fprintf(stderr, "Invalid download rate: %s\n", optarg);
                    return -1;
                }
                args->download_bps = value;
                break;
            }
            case OPT_UPLOAD_BPS: {
                unsigned long value;
                if (parse_ulong(optarg, &value) < 0) {
                    fprintf(stderr, "Invalid upload rate: %s\n", optarg);
                    return -1;
                }
                args->upload_bps = value;
                break;
            }
            case OPT_MAC_ADDRESS:
                strncpy(args->mac_address, optarg, sizeof(args->mac_address) - 1);
                break;
            case OPT_LOG_PATH:
                strncpy(args->log_path, optarg, sizeof(args->log_path) - 1);
                break;
            case OPT_EXPORT_PATH:
                strncpy(args->export_path, optarg, sizeof(args->export_path) - 1);
                break;
            case OPT_WORDLIST:
                strncpy(args->wordlist, optarg, sizeof(args->wordlist) - 1);
                break;
            case OPT_INTERFACE:
                strncpy(args->interface, optarg, sizeof(args->interface) - 1);
                break;
            case OPT_PORTS:
                strncpy(args->rule, optarg, sizeof(args->rule) - 1);
                break;
            case OPT_RECORD_TYPE:
                strncpy(args->record_type, optarg, sizeof(args->record_type) - 1);
                break;
            case OPT_PROTOCOL:
                strncpy(args->protocol, optarg, sizeof(args->protocol) - 1);
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
                print_usage();
                return -1;
        }
    }

    if (args->cmd == CMD_NONE) {
        print_usage();
        return -1;
    }

    return 0;
}
