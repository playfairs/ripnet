#include "ripnet/packet.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>

static pcap_t *handle = NULL;
static packet_counters_t counters;
static flow_table_t flow_table;
static int packet_limit = 0;
static volatile sig_atomic_t should_stop = 0;

void sigint_handler(int signum)
{
    (void)signum;
    should_stop = 1;
}

void init_packet_counters(packet_counters_t *counters)
{
    memset(counters, 0, sizeof(packet_counters_t));
}

void init_flow_table(flow_table_t *table)
{
    table->capacity = 1024;
    table->entries = xcalloc(table->capacity, sizeof(flow_entry_t));
    table->count = 0;
}

void free_flow_table(flow_table_t *table)
{
    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

flow_entry_t *find_or_create_flow(flow_table_t *table, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol)
{
    for (int i = 0; i < table->count; i++) {
        flow_entry_t *entry = &table->entries[i];
        if (entry->src_ip == src_ip && entry->dst_ip == dst_ip &&
            entry->src_port == src_port && entry->dst_port == dst_port &&
            entry->protocol == protocol) {
            return entry;
        }
    }

    if (table->count >= table->capacity) {
        table->capacity *= 2;
        table->entries = xrealloc(table->entries, table->capacity * sizeof(flow_entry_t));
    }

    flow_entry_t *entry = &table->entries[table->count++];
    entry->src_ip = src_ip;
    entry->dst_ip = dst_ip;
    entry->src_port = src_port;
    entry->dst_port = dst_port;
    entry->protocol = protocol;
    entry->packet_count = 0;
    entry->byte_count = 0;

    return entry;
}

int parse_ethernet(const u_char *packet, uint32_t *ethertype)
{
    *ethertype = (packet[12] << 8) | packet[13];
    return 0;
}

int parse_ipv4(const u_char *packet, uint32_t *src_ip, uint32_t *dst_ip, uint8_t *protocol, uint32_t *payload_offset)
{
    *src_ip = ntohl(*(uint32_t *)(packet + 12));
    *dst_ip = ntohl(*(uint32_t *)(packet + 16));
    *protocol = packet[9];
    uint8_t ihl = (packet[0] & 0x0F) * 4;
    *payload_offset = ihl;
    return 0;
}

int parse_ipv6(const u_char *packet, uint8_t *src_ip, uint8_t *dst_ip, uint8_t *next_header, uint32_t *payload_offset)
{
    memcpy(src_ip, packet + 8, 16);
    memcpy(dst_ip, packet + 24, 16);
    *next_header = packet[6];
    *payload_offset = 40;
    return 0;
}

int parse_tcp(const u_char *packet, uint16_t *src_port, uint16_t *dst_port)
{
    *src_port = ntohs(*(uint16_t *)packet);
    *dst_port = ntohs(*(uint16_t *)(packet + 2));
    return 0;
}

int parse_udp(const u_char *packet, uint16_t *src_port, uint16_t *dst_port)
{
    *src_port = ntohs(*(uint16_t *)packet);
    *dst_port = ntohs(*(uint16_t *)(packet + 2));
    return 0;
}

int parse_icmp(const u_char *packet)
{
    (void)packet;
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;

    counters.total++;

    uint32_t ethertype;
    if (parse_ethernet(packet, &ethertype) == 0) {
        counters.ethernet++;

        if (ethertype == 0x0800) {
            counters.ipv4++;

            uint32_t src_ip, dst_ip;
            uint8_t protocol;
            uint32_t payload_offset;

            if (parse_ipv4(packet + 14, &src_ip, &dst_ip, &protocol, &payload_offset) == 0) {
                const u_char *payload = packet + 14 + payload_offset;

                if (protocol == 6) {
                    counters.tcp++;

                    uint16_t src_port, dst_port;
                    if (parse_tcp(payload, &src_port, &dst_port) == 0) {
                        flow_entry_t *flow = find_or_create_flow(&flow_table, src_ip, dst_ip, src_port, dst_port, protocol);
                        flow->packet_count++;
                        flow->byte_count += header->len;
                    }
                } else if (protocol == 17) {
                    counters.udp++;

                    uint16_t src_port, dst_port;
                    if (parse_udp(payload, &src_port, &dst_port) == 0) {
                        flow_entry_t *flow = find_or_create_flow(&flow_table, src_ip, dst_ip, src_port, dst_port, protocol);
                        flow->packet_count++;
                        flow->byte_count += header->len;
                    }
                } else if (protocol == 1) {
                    counters.icmp++;
                }
            }
        } else if (ethertype == 0x86DD) {
            counters.ipv6++;

            uint8_t src_ip[16], dst_ip[16];
            uint8_t next_header;
            uint32_t payload_offset;

            if (parse_ipv6(packet + 14, src_ip, dst_ip, &next_header, &payload_offset) == 0) {
                if (next_header == 6) {
                    counters.tcp++;
                } else if (next_header == 17) {
                    counters.udp++;
                } else if (next_header == 58) {
                    counters.icmp++;
                }
            }
        } else {
            counters.other++;
        }
    } else {
        counters.other++;
    }

    if (packet_limit > 0 && counters.total >= (uint64_t)packet_limit) {
        should_stop = 1;
    }
}

void print_packet_summary(const packet_counters_t *counters)
{
    printf("Packet Capture Summary:\n");
    printf("  Total packets: %" PRIu64 "\n", counters->total);
    printf("  Ethernet: %" PRIu64 "\n", counters->ethernet);
    printf("  IPv4: %" PRIu64 "\n", counters->ipv4);
    printf("  IPv6: %" PRIu64 "\n", counters->ipv6);
    printf("  TCP: %" PRIu64 "\n", counters->tcp);
    printf("  UDP: %" PRIu64 "\n", counters->udp);
    printf("  ICMP: %" PRIu64 "\n", counters->icmp);
    printf("  Other: %" PRIu64 "\n", counters->other);
}

void print_flows(const flow_table_t *table)
{
    printf("\nTop Flows:\n");
    for (int i = 0; i < table->count && i < 20; i++) {
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = htonl(table->entries[i].src_ip);
        dst_addr.s_addr = htonl(table->entries[i].dst_ip);

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

        const char *proto = table->entries[i].protocol == 6 ? "TCP" : 
                           table->entries[i].protocol == 17 ? "UDP" : "OTHER";

        printf("  %s %s:%u -> %s:%u (%" PRIu64 " packets, %" PRIu64 " bytes)\n",
               proto, src_ip, table->entries[i].src_port, dst_ip, table->entries[i].dst_port,
               table->entries[i].packet_count, table->entries[i].byte_count);
    }
}

int start_capture(const char *iface, const char *filter, int count, int promisc)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    handle = pcap_open_live(iface, BUFSIZ, promisc, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", iface, errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers\n", iface);
        pcap_close(handle);
        return -1;
    }

    if (filter && strlen(filter) > 0) {
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Could not parse filter %s: %s\n", filter, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Could not install filter %s: %s\n", filter, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return -1;
        }

        pcap_freecode(&fp);
    }

    init_packet_counters(&counters);
    init_flow_table(&flow_table);
    packet_limit = count;
    should_stop = 0;

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("Starting capture on interface %s\n", iface);
    if (filter && strlen(filter) > 0) {
        printf("Filter: %s\n", filter);
    }
    if (count > 0) {
        printf("Packet limit: %d\n", count);
    }
    printf("Press Ctrl+C to stop\n\n");

    pcap_loop(handle, -1, process_packet, NULL);

    pcap_close(handle);
    handle = NULL;

    print_packet_summary(&counters);
    print_flows(&flow_table);

    free_flow_table(&flow_table);

    return 0;
}

void stop_capture(void)
{
    if (handle) {
        pcap_breakloop(handle);
    }
}