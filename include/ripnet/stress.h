#ifndef RIPNET_STRESS_H
#define RIPNET_STRESS_H

#include <stdint.h>

typedef struct {
    uint64_t total_connections;
    uint64_t successful_connections;
    uint64_t failed_connections;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    double min_latency_ms;
    double max_latency_ms;
    double avg_latency_ms;
    double p50_latency_ms;
    double p95_latency_ms;
    double p99_latency_ms;
    double duration_sec;
    double throughput_mbps;
} stress_result_t;

typedef struct {
    char *host;
    int port;
    int concurrency;
    int duration_sec;
    int rate_limit;
    int is_http;
    char *http_path;
} stress_config_t;

int run_tcp_stress(const stress_config_t *config, stress_result_t *result);
int run_http_stress(const stress_config_t *config, stress_result_t *result);
void print_stress_results(const stress_result_t *result);
void print_stress_json(const stress_result_t *result);
int calculate_percentiles(double *latencies, int count, double *p50, double *p95, double *p99);
int packet_flood(const char *iface, const char *target_ip, int port, int duration_sec, uint64_t packets_per_sec);
int scan_ports(const char *target_ip, int start_port, int end_port, int timeout_ms);
int detect_vulnerabilities(const char *target_ip, int port);

#endif