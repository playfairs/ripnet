#include "ripnet/monitor.h"
#include "ripnet/stats.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

static volatile sig_atomic_t monitor_running = 0;
static char monitor_interface[32] = {0};

static void monitor_signal_handler(int signum)
{
    (void)signum;
    monitor_running = 0;
}

int monitor_start(const char *interface)
{
    strncpy(monitor_interface, interface, sizeof(monitor_interface) - 1);
    monitor_running = 1;
    
    signal(SIGINT, monitor_signal_handler);
    signal(SIGTERM, monitor_signal_handler);
    
    printf(COLOR_BOLD COLOR_CYAN "NETWORK MONITOR\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Press Ctrl+C to stop\n\n");
    
    return 0;
}

int monitor_stop(void)
{
    monitor_running = 0;
    printf(COLOR_BOLD COLOR_CYAN "\nMONITOR STOPPED\n" COLOR_RESET);
    return 0;
}

int monitor_status(monitor_snapshot_t *snapshot)
{
    interface_stats_t stats;
    
    if (strlen(monitor_interface) == 0) {
        fprintf(stderr, "Monitor not started\n");
        return -1;
    }
    
    if (get_interface_stats(monitor_interface, &stats) < 0) {
        fprintf(stderr, "Could not get interface statistics\n");
        return -1;
    }
    
    snapshot->current.rx_packets = stats.rx_packets;
    snapshot->current.tx_packets = stats.tx_packets;
    snapshot->current.rx_bytes = stats.rx_bytes;
    snapshot->current.tx_bytes = stats.tx_bytes;
    snapshot->current.rx_errors = stats.rx_errors;
    snapshot->current.tx_errors = stats.tx_errors;
    snapshot->current.rx_dropped = stats.rx_dropped;
    snapshot->current.tx_dropped = stats.tx_dropped;
    
    if (snapshot->previous.rx_bytes > 0) {
        uint64_t rx_delta = snapshot->current.rx_bytes - snapshot->previous.rx_bytes;
        uint64_t tx_delta = snapshot->current.tx_bytes - snapshot->previous.tx_bytes;
        
        snapshot->current.rx_rate_mbps = (double)rx_delta / 1000000.0;
        snapshot->current.tx_rate_mbps = (double)tx_delta / 1000000.0;
        
        uint64_t packet_delta = (snapshot->current.rx_packets + snapshot->current.tx_packets) - 
                               (snapshot->previous.rx_packets + snapshot->previous.tx_packets);
        uint64_t error_delta = (snapshot->current.rx_errors + snapshot->current.tx_errors) - 
                               (snapshot->previous.rx_errors + snapshot->previous.tx_errors);
        
        if (packet_delta > 0) {
            snapshot->current.packet_loss = (double)error_delta / packet_delta * 100.0;
        } else {
            snapshot->current.packet_loss = 0.0;
        }
    }
    
    snapshot->previous = snapshot->current;
    
    return 0;
}

int monitor_alert(const char *interface, double threshold_mbps)
{
    monitor_snapshot_t snapshot;
    
    printf(COLOR_BOLD COLOR_CYAN "MONITOR ALERT\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Threshold: %.2f Mbps\n", threshold_mbps);
    
    monitor_start(interface);
    
    while (monitor_running) {
        monitor_status(&snapshot);
        
        if (snapshot.current.rx_rate_mbps > threshold_mbps || 
            snapshot.current.tx_rate_mbps > threshold_mbps) {
            printf(COLOR_BOLD COLOR_RED "[ALERT] " COLOR_RESET "Bandwidth exceeded threshold!\n");
            printf("  RX: %.2f Mbps, TX: %.2f Mbps\n", 
                   snapshot.current.rx_rate_mbps, snapshot.current.tx_rate_mbps);
        }
        
        print_monitor_status(&snapshot);
        sleep(1);
    }
    
    return 0;
}

int monitor_log(const char *interface, const char *log_path)
{
    (void)interface;
    (void)log_path;
    
    printf(COLOR_BOLD COLOR_CYAN "MONITOR LOG\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Log path: %s\n", log_path);
    printf("  " COLOR_YELLOW "Monitor logging requires file I/O implementation\n" COLOR_RESET);
    return -1;
}

int monitor_export(const char *interface, const char *export_path)
{
    (void)interface;
    (void)export_path;
    
    printf(COLOR_BOLD COLOR_CYAN "MONITOR EXPORT\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  Export path: %s\n", export_path);
    printf("  " COLOR_YELLOW "Monitor export requires data serialization\n" COLOR_RESET);
    return -1;
}

void print_monitor_status(const monitor_snapshot_t *snapshot)
{
    char rx_buf[32], tx_buf[32];
    format_bytes(snapshot->current.rx_bytes, rx_buf, sizeof(rx_buf));
    format_bytes(snapshot->current.tx_bytes, tx_buf, sizeof(tx_buf));
    
    printf(COLOR_BOLD "[MONITOR] " COLOR_RESET);
    printf("RX: " COLOR_GREEN "%.2f Mbps (%s)" COLOR_RESET " | ", 
           snapshot->current.rx_rate_mbps, rx_buf);
    printf("TX: " COLOR_GREEN "%.2f Mbps (%s)" COLOR_RESET " | ", 
           snapshot->current.tx_rate_mbps, tx_buf);
    printf("Loss: " COLOR_YELLOW "%.2f%%" COLOR_RESET "\n", snapshot->current.packet_loss);
}
