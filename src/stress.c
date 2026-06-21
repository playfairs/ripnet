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

#if defined(__linux__)
#include <netinet/tcp.h>
#endif

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

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
    int opt = 1;

    while (!*ctx->should_stop) {
        wctx.sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (wctx.sockfd < 0) {
            ctx->result->failed_connections++;
            ctx->result->total_connections++;
            continue;
        }

        setsockopt(wctx.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#if defined(__linux__)
        setsockopt(wctx.sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#endif

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

        ssize_t sent = send(wctx.sockfd, full_request, request_len, MSG_NOSIGNAL);
        if (sent > 0) {
            wctx.bytes_sent = sent;
            ctx->result->total_bytes_sent += sent;

            char response[8192];
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

    printf(COLOR_BOLD COLOR_CYAN "TCP STRESS TEST\n");
    printf(COLOR_RESET "  Target: " COLOR_BOLD COLOR_GREEN "%s:%d\n", config->host, config->port);
    printf(COLOR_RESET "  Duration: " COLOR_BOLD COLOR_YELLOW "%d seconds\n", config->duration_sec);
    printf(COLOR_RESET "  Concurrency: " COLOR_BOLD COLOR_MAGENTA "%d workers\n", config->concurrency);
    printf("\n");

    for (int elapsed = 0; elapsed < config->duration_sec; elapsed++) {
        double conn_rate = (double)result->total_connections / (elapsed + 1);
        double success_rate = result->total_connections > 0 ? (double)result->successful_connections / result->total_connections * 100.0 : 0.0;
        char rate_buf[32];
        format_rate(result->total_bytes_sent * 8 / (elapsed + 1), rate_buf, sizeof(rate_buf));

        printf(COLOR_BOLD "\r[" COLOR_CYAN "%02d/%02d" COLOR_RESET "] " COLOR_GREEN "Conn: %" PRIu64 COLOR_RESET " | " COLOR_YELLOW "Success: %" PRIu64 COLOR_RESET " (%.1f%%) | " COLOR_RED "Failed: %" PRIu64 COLOR_RESET " | " COLOR_MAGENTA "Rate: %.1f/s" COLOR_RESET " | " COLOR_BLUE "BW: %s" COLOR_RESET,
               elapsed + 1, config->duration_sec, result->total_connections, result->successful_connections, success_rate, result->failed_connections, conn_rate, rate_buf);
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
    char sent_buf[32], recv_buf[32];
    format_bytes(result->total_bytes_sent, sent_buf, sizeof(sent_buf));
    format_bytes(result->total_bytes_received, recv_buf, sizeof(recv_buf));

    double success_rate = result->total_connections > 0 ? (double)result->successful_connections / result->total_connections * 100.0 : 0.0;
    double conn_rate = result->total_connections / result->duration_sec;

    printf(COLOR_BOLD COLOR_CYAN "\nSTRESS TEST RESULTS\n");
    printf(COLOR_RESET "  Duration:        " COLOR_BOLD COLOR_YELLOW "%.2f seconds\n", result->duration_sec);
    printf(COLOR_RESET "  Total Conn:      " COLOR_BOLD COLOR_GREEN "%" PRIu64 "\n", result->total_connections);
    printf(COLOR_RESET "  Successful:      " COLOR_BOLD COLOR_GREEN "%" PRIu64 COLOR_RESET " (%.2f%%)\n", result->successful_connections, success_rate);
    printf(COLOR_RESET "  Failed:          " COLOR_BOLD COLOR_RED "%" PRIu64 "\n", result->failed_connections);
    printf(COLOR_RESET "  Conn Rate:       " COLOR_BOLD COLOR_MAGENTA "%.1f conn/s\n", conn_rate);
    printf(COLOR_RESET "  Bytes Sent:      " COLOR_BOLD COLOR_BLUE "%s\n", sent_buf);
    printf(COLOR_RESET "  Bytes Received:  " COLOR_BOLD COLOR_BLUE "%s\n", recv_buf);
    printf(COLOR_RESET "  Throughput:      " COLOR_BOLD COLOR_BLUE "%.2f Mbps\n", result->throughput_mbps);
    printf(COLOR_RESET "  Latency (ms):\n");
    printf(COLOR_RESET "    Min:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->min_latency_ms);
    printf(COLOR_RESET "    Max:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->max_latency_ms);
    printf(COLOR_RESET "    Avg:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->avg_latency_ms);
    printf(COLOR_RESET "    P50:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->p50_latency_ms);
    printf(COLOR_RESET "    P95:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->p95_latency_ms);
    printf(COLOR_RESET "    P99:           " COLOR_BOLD COLOR_YELLOW "%.2f\n", result->p99_latency_ms);
    printf(COLOR_RESET "\n");
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