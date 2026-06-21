#ifndef RIPNET_PACKET_H
#define RIPNET_PACKET_H

#if defined(__linux__)
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#define __FAVOR_BSD 1
#define _GNU_SOURCE 1
#include <sys/types.h>
#ifndef u_int
typedef unsigned int u_int;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_int32_t
typedef unsigned int u_int32_t;
#endif
#ifndef u_int16_t
typedef unsigned short u_int16_t;
#endif
#ifndef u_int8_t
typedef unsigned char u_int8_t;
#endif
#ifndef bpf_u_int32
typedef unsigned int bpf_u_int32;
#endif
#endif

#include <pcap.h>
#include <stdint.h>

typedef struct {
    uint64_t total;
    uint64_t ethernet;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t other;
} packet_counters_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t packet_count;
    uint64_t byte_count;
} flow_entry_t;

typedef struct {
    flow_entry_t *entries;
    int count;
    int capacity;
} flow_table_t;

int start_capture(const char *iface, const char *filter, int count, int promisc);
void stop_capture(void);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_summary(const packet_counters_t *counters);
void init_packet_counters(packet_counters_t *counters);
void init_flow_table(flow_table_t *table);
void free_flow_table(flow_table_t *table);
flow_entry_t *find_or_create_flow(flow_table_t *table, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol);
void print_flows(const flow_table_t *table);
int parse_ethernet(const u_char *packet, uint32_t *ethertype);
int parse_ipv4(const u_char *packet, uint32_t *src_ip, uint32_t *dst_ip, uint8_t *protocol, uint32_t *payload_offset);
int parse_ipv6(const u_char *packet, uint8_t *src_ip, uint8_t *dst_ip, uint8_t *next_header, uint32_t *payload_offset);
int parse_tcp(const u_char *packet, uint16_t *src_port, uint16_t *dst_port);
int parse_udp(const u_char *packet, uint16_t *src_port, uint16_t *dst_port);
int parse_icmp(const u_char *packet);

#endif