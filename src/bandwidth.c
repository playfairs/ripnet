#include "ripnet/bandwidth.h"
#include "ripnet/stats.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

int bandwidth_test(const char *interface, bandwidth_result_t *result)
{
    interface_stats_t stats_before, stats_after;
    
    memset(result, 0, sizeof(bandwidth_result_t));
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH TEST\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Measuring for 5 seconds...\n\n");
    
    if (get_interface_stats(interface, &stats_before) < 0) {
        fprintf(stderr, "Could not get interface statistics\n");
        return -1;
    }
    
    sleep(5);
    
    if (get_interface_stats(interface, &stats_after) < 0) {
        fprintf(stderr, "Could not get interface statistics\n");
        return -1;
    }
    
    bandwidth_stats_t *bw = &result->interfaces[result->interface_count];
    strncpy(bw->interface, interface, sizeof(bw->interface) - 1);
    
    uint64_t rx_delta = stats_after.rx_bytes - stats_before.rx_bytes;
    uint64_t tx_delta = stats_after.tx_bytes - stats_before.tx_bytes;
    
    bw->rx_bytes = stats_after.rx_bytes;
    bw->tx_bytes = stats_after.tx_bytes;
    bw->rx_rate_bps = rx_delta / 5;
    bw->tx_rate_bps = tx_delta / 5;
    bw->rx_rate_mbps = (double)bw->rx_rate_bps / 1000000.0;
    bw->tx_rate_mbps = (double)bw->tx_rate_bps / 1000000.0;
    bw->total_rate_mbps = bw->rx_rate_mbps + bw->tx_rate_mbps;
    
    result->interface_count++;
    result->total_bandwidth_mbps += bw->total_rate_mbps;
    
    printf("  RX Rate: " COLOR_BOLD COLOR_GREEN "%.2f Mbps\n" COLOR_RESET, bw->rx_rate_mbps);
    printf("  TX Rate: " COLOR_BOLD COLOR_GREEN "%.2f Mbps\n" COLOR_RESET, bw->tx_rate_mbps);
    printf("  Total: " COLOR_BOLD COLOR_CYAN "%.2f Mbps\n" COLOR_RESET, bw->total_rate_mbps);
    
    return 0;
}

int bandwidth_speedtest(const char *server, bandwidth_result_t *result)
{
    (void)server;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH SPEEDTEST\n" COLOR_RESET);
    printf("  Server: %s\n", server);
    printf("  " COLOR_YELLOW "Speedtest requires external service integration\n" COLOR_RESET);
    return -1;
}

int bandwidth_monitor(const char *interface, int interval_sec)
{
    interface_stats_t stats_before, stats_after;
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH MONITOR\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Interval: %d seconds\n", interval_sec);
    printf("  Press Ctrl+C to stop\n\n");
    
    if (get_interface_stats(interface, &stats_before) < 0) {
        fprintf(stderr, "Could not get interface statistics\n");
        return -1;
    }
    
    while (1) {
        sleep(interval_sec);
        
        if (get_interface_stats(interface, &stats_after) < 0) {
            fprintf(stderr, "Could not get interface statistics\n");
            break;
        }
        
        uint64_t rx_delta = stats_after.rx_bytes - stats_before.rx_bytes;
        uint64_t tx_delta = stats_after.tx_bytes - stats_before.tx_bytes;
        
        double rx_rate_mbps = (double)(rx_delta / interval_sec) / 1000000.0;
        double tx_rate_mbps = (double)(tx_delta / interval_sec) / 1000000.0;
        
        char rx_buf[32], tx_buf[32];
        format_bytes(rx_delta, rx_buf, sizeof(rx_buf));
        format_bytes(tx_delta, tx_buf, sizeof(tx_buf));
        
        printf(COLOR_BOLD "[%s] " COLOR_RESET "RX: " COLOR_GREEN "%.2f Mbps (%s)" COLOR_RESET " | TX: " COLOR_GREEN "%.2f Mbps (%s)" COLOR_RESET "\n",
               interface, rx_rate_mbps, rx_buf, tx_rate_mbps, tx_buf);
        
        stats_before = stats_after;
    }
    
    return 0;
}

int bandwidth_history(const char *interface, int hours)
{
    (void)interface;
    (void)hours;
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH HISTORY\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Hours: %d\n", hours);
    printf("  " COLOR_YELLOW "Bandwidth history requires data logging system\n" COLOR_RESET);
    return -1;
}

int bandwidth_limit(const char *interface, uint64_t max_bps)
{
    (void)interface;
    (void)max_bps;
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH LIMIT\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Max Rate: %" PRIu64 " bps\n", max_bps);
    printf("  " COLOR_YELLOW "Bandwidth limiting requires tc (traffic control)\n" COLOR_RESET);
    return -1;
}

int bandwidth_shaper(const char *interface, uint64_t download_bps, uint64_t upload_bps)
{
    (void)interface;
    (void)download_bps;
    (void)upload_bps;
    
    printf(COLOR_BOLD COLOR_CYAN "BANDWIDTH SHAPER\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Download: %" PRIu64 " bps, Upload: %" PRIu64 " bps\n", download_bps, upload_bps);
    printf("  " COLOR_YELLOW "Bandwidth shaping requires tc (traffic control)\n" COLOR_RESET);
    return -1;
}

void print_bandwidth_results(const bandwidth_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "\nBANDWIDTH RESULTS\n" COLOR_RESET);
    printf("  Interfaces monitored: %d\n", result->interface_count);
    printf("  Total bandwidth: %.2f Mbps\n\n", result->total_bandwidth_mbps);
    
    for (int i = 0; i < result->interface_count; i++) {
        const bandwidth_stats_t *bw = &result->interfaces[i];
        char rx_buf[32], tx_buf[32];
        format_bytes(bw->rx_bytes, rx_buf, sizeof(rx_buf));
        format_bytes(bw->tx_bytes, tx_buf, sizeof(tx_buf));
        
        printf("  %s:\n", bw->interface);
        printf("    RX: %s (%.2f Mbps)\n", rx_buf, bw->rx_rate_mbps);
        printf("    TX: %s (%.2f Mbps)\n", tx_buf, bw->tx_rate_mbps);
        printf("    Total: %.2f Mbps\n\n", bw->total_rate_mbps);
    }
}
