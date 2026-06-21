#include "ripnet/stress.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <fcntl.h>
#include <netdb.h>
#include <inttypes.h>

typedef struct {
    int sockfd;
    struct sockaddr_in addr;
    double latency_ms;
    int success;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} worker_context_t;

typedef struct {
    const stress_config_t *config;
    stress_result_t *result;
    double *latencies;
    int *latency_index;
    pthread_mutex_t *latency_mutex;
    volatile int *should_stop;
    struct in_addr target_ip;
} thread_context_t;

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

int calculate_percentiles(double *latencies, int count, double *p50, double *p95, double *p99)
{
    if (count == 0) {
        *p50 = 0;
        *p95 = 0;
        *p99 = 0;
        return 0;
    }

    qsort(latencies, count, sizeof(double), compare_double);

    *p50 = latencies[count * 50 / 100];
    *p95 = latencies[count * 95 / 100];
    *p99 = latencies[count * 99 / 100];

    return 0;
}

static void *tcp_worker(void *arg)
{
    thread_context_t *ctx = (thread_context_t *)arg;
    worker_context_t wctx;
    struct timespec start, end;

    while (!*ctx->should_stop) {
        wctx.sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (wctx.sockfd < 0) {
            ctx->result->failed_connections++;
            ctx->result->total_connections++;
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ctx->config->port);
        addr.sin_addr = ctx->target_ip;

        if (connect(wctx.sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(wctx.sockfd);
            ctx->result->failed_connections++;
            ctx->result->total_connections++;
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        wctx.latency_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
        wctx.success = 1;

        const char *request = "GET / HTTP/1.1\r\nHost: ";
        const char *request_end = "\r\nConnection: close\r\n\r\n";
        char full_request[512];
        int request_len = snprintf(full_request, sizeof(full_request), "%s%s%s", request, ctx->config->host, request_end);

        ssize_t sent = send(wctx.sockfd, full_request, request_len, 0);
        if (sent > 0) {
            wctx.bytes_sent = sent;
            ctx->result->total_bytes_sent += sent;

            char response[4096];
            ssize_t received = recv(wctx.sockfd, response, sizeof(response), 0);
            if (received > 0) {
                wctx.bytes_received = received;
                ctx->result->total_bytes_received += received;
            }
        }

        pthread_mutex_lock(ctx->latency_mutex);
        if (*ctx->latency_index < ctx->config->concurrency * 1000) {
            ctx->latencies[*ctx->latency_index] = wctx.latency_ms;
            (*ctx->latency_index)++;
        }
        pthread_mutex_unlock(ctx->latency_mutex);

        ctx->result->successful_connections++;
        ctx->result->total_connections++;

        if (wctx.latency_ms < ctx->result->min_latency_ms || ctx->result->min_latency_ms == 0) {
            ctx->result->min_latency_ms = wctx.latency_ms;
        }
        if (wctx.latency_ms > ctx->result->max_latency_ms) {
            ctx->result->max_latency_ms = wctx.latency_ms;
        }

        close(wctx.sockfd);

        if (ctx->config->rate_limit > 0) {
            usleep(1000000 / ctx->config->rate_limit);
        }
    }

    return NULL;
}

int run_tcp_stress(const stress_config_t *config, stress_result_t *result)
{
    pthread_t *threads;
    thread_context_t ctx;
    pthread_mutex_t latency_mutex;
    double *latencies;
    int latency_index = 0;
    volatile int should_stop = 0;
    struct addrinfo hints, *res;

    memset(result, 0, sizeof(stress_result_t));
    result->min_latency_ms = 0;
    result->max_latency_ms = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(config->host, NULL, &hints, &res) != 0) {
        fprintf(stderr, "Could not resolve host %s\n", config->host);
        return -1;
    }

    ctx.target_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    threads = xmalloc(config->concurrency * sizeof(pthread_t));
    latencies = xmalloc(config->concurrency * 1000 * sizeof(double));
    pthread_mutex_init(&latency_mutex, NULL);

    ctx.config = config;
    ctx.result = result;
    ctx.latencies = latencies;
    ctx.latency_index = &latency_index;
    ctx.latency_mutex = &latency_mutex;
    ctx.should_stop = &should_stop;

    for (int i = 0; i < config->concurrency; i++) {
        pthread_create(&threads[i], NULL, tcp_worker, &ctx);
    }

    printf("Running TCP stress test for %d seconds with %d concurrent connections\n", config->duration_sec, config->concurrency);
    printf("Target: %s:%d\n", config->host, config->port);
    printf("\n");

    for (int elapsed = 0; elapsed < config->duration_sec; elapsed++) {
        printf("\rProgress: %d/%d seconds | Connections: %" PRIu64 " | Success: %" PRIu64 " | Failed: %" PRIu64,
               elapsed + 1, config->duration_sec, result->total_connections, result->successful_connections, result->failed_connections);
        fflush(stdout);
        sleep(1);
    }
    printf("\n\n");

    should_stop = 1;

    for (int i = 0; i < config->concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&latency_mutex);

    if (latency_index > 0) {
        double sum = 0;
        for (int i = 0; i < latency_index; i++) {
            sum += latencies[i];
        }
        result->avg_latency_ms = sum / latency_index;

        calculate_percentiles(latencies, latency_index, &result->p50_latency_ms, &result->p95_latency_ms, &result->p99_latency_ms);
    }

    result->duration_sec = config->duration_sec;
    result->throughput_mbps = (result->total_bytes_sent + result->total_bytes_received) * 8.0 / (config->duration_sec * 1000000.0);

    free(threads);
    free(latencies);

    return 0;
}

int run_http_stress(const stress_config_t *config, stress_result_t *result)
{
    (void)config;
    (void)result;
    fprintf(stderr, "HTTP stress test not yet implemented\n");
    return -1;
}

void print_stress_results(const stress_result_t *result)
{
    printf("\nStress Test Results:\n");
    printf("  Duration: %.2f seconds\n", result->duration_sec);
    printf("  Total connections: %" PRIu64 "\n", result->total_connections);
    printf("  Successful: %" PRIu64 "\n", result->successful_connections);
    printf("  Failed: %" PRIu64 "\n", result->failed_connections);
    printf("  Success rate: %.2f%%\n", result->total_connections > 0 ? (double)result->successful_connections / result->total_connections * 100.0 : 0.0);
    printf("  Bytes sent: %" PRIu64 "\n", result->total_bytes_sent);
    printf("  Bytes received: %" PRIu64 "\n", result->total_bytes_received);
    printf("  Latency (ms):\n");
    printf("    Min: %.2f\n", result->min_latency_ms);
    printf("    Max: %.2f\n", result->max_latency_ms);
    printf("    Avg: %.2f\n", result->avg_latency_ms);
    printf("    P50: %.2f\n", result->p50_latency_ms);
    printf("    P95: %.2f\n", result->p95_latency_ms);
    printf("    P99: %.2f\n", result->p99_latency_ms);
    printf("  Throughput: %.2f Mbps\n", result->throughput_mbps);
}

void print_stress_json(const stress_result_t *result)
{
    printf("{\n");
    printf("  \"duration_sec\": %.2f,\n", result->duration_sec);
    printf("  \"total_connections\": %" PRIu64 ",\n", result->total_connections);
    printf("  \"successful_connections\": %" PRIu64 ",\n", result->successful_connections);
    printf("  \"failed_connections\": %" PRIu64 ",\n", result->failed_connections);
    printf("  \"success_rate\": %.2f,\n", result->total_connections > 0 ? (double)result->successful_connections / result->total_connections * 100.0 : 0.0);
    printf("  \"total_bytes_sent\": %" PRIu64 ",\n", result->total_bytes_sent);
    printf("  \"total_bytes_received\": %" PRIu64 ",\n", result->total_bytes_received);
    printf("  \"min_latency_ms\": %.2f,\n", result->min_latency_ms);
    printf("  \"max_latency_ms\": %.2f,\n", result->max_latency_ms);
    printf("  \"avg_latency_ms\": %.2f,\n", result->avg_latency_ms);
    printf("  \"p50_latency_ms\": %.2f,\n", result->p50_latency_ms);
    printf("  \"p95_latency_ms\": %.2f,\n", result->p95_latency_ms);
    printf("  \"p99_latency_ms\": %.2f,\n", result->p99_latency_ms);
    printf("  \"throughput_mbps\": %.2f\n", result->throughput_mbps);
    printf("}\n");
}

int packet_flood(const char *iface, const char *target_ip, int port, int duration_sec, uint64_t packets_per_sec)
{
    (void)iface;
    (void)target_ip;
    (void)port;
    (void)duration_sec;
    (void)packets_per_sec;
    fprintf(stderr, "Packet flood requires raw socket access and is only available on authorized systems\n");
    return -1;
}

int scan_ports(const char *target_ip, int start_port, int end_port, int timeout_ms)
{
    struct sockaddr_in addr;
    int sockfd;
    struct timeval timeout;
    fd_set fdset;
    int open_ports = 0;

    printf("Scanning ports %d-%d on %s\n", start_port, end_port, target_ip);

    for (int port = start_port; port <= end_port; port++) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            continue;
        }

        fcntl(sockfd, F_SETFL, O_NONBLOCK);

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip, &addr.sin_addr);

        connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);

        if (select(sockfd + 1, NULL, &fdset, NULL, &timeout) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

            if (so_error == 0) {
                printf("Port %d: OPEN\n", port);
                open_ports++;
            }
        }

        close(sockfd);
    }

    printf("Scan complete. Found %d open ports.\n", open_ports);
    return 0;
}

int detect_vulnerabilities(const char *target_ip, int port)
{
    (void)target_ip;
    (void)port;
    fprintf(stderr, "Vulnerability scanning requires explicit authorization and configuration\n");
    return -1;
}