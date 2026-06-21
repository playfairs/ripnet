#include "ripnet/netstat.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

int netstat_connections(netstat_result_t *result)
{
    char command[1024];
    FILE *fp;
    char line[1024];
    
    memset(result, 0, sizeof(netstat_result_t));
    
    printf(COLOR_BOLD COLOR_CYAN "NETSTAT CONNECTIONS\n" COLOR_RESET);
    
#if defined(__APPLE__) || defined(__FreeBSD__)
    snprintf(command, sizeof(command), "netstat -an 2>/dev/null");
#elif defined(__linux__)
    snprintf(command, sizeof(command), "ss -tunap 2>/dev/null");
#else
    fprintf(stderr, "Netstat not supported on this platform\n");
    return -1;
#endif
    
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to execute netstat\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL && result->connection_count < 4096) {
        if (strstr(line, "Proto") != NULL || strstr(line, "State") != NULL) {
            continue;
        }
        
        connection_info_t *conn = &result->connections[result->connection_count];
        memset(conn, 0, sizeof(connection_info_t));
        
        char *token = strtok(line, " \t\n");
        if (token == NULL) continue;
        strncpy(conn->protocol, token, sizeof(conn->protocol) - 1);
        
        token = strtok(NULL, " \t\n");
        if (token == NULL) continue;
        strncpy(conn->local_address, token, sizeof(conn->local_address) - 1);
        
        token = strtok(NULL, " \t\n");
        if (token == NULL) continue;
        strncpy(conn->remote_address, token, sizeof(conn->remote_address) - 1);
        
        token = strtok(NULL, " \t\n");
        if (token != NULL) strncpy(conn->state, token, sizeof(conn->state) - 1);
        
        if (strcmp(conn->protocol, "tcp") == 0) result->tcp_count++;
        else if (strcmp(conn->protocol, "udp") == 0) result->udp_count++;
        
        if (strstr(conn->state, "LISTEN") != NULL) result->listening_count++;
        if (strstr(conn->state, "ESTABLISHED") != NULL) result->established_count++;
        
        result->connection_count++;
    }
    
    pclose(fp);
    
    printf("  Total connections: %d\n", result->connection_count);
    printf("  TCP: %d, UDP: %d\n", result->tcp_count, result->udp_count);
    printf("  Listening: %d, Established: %d\n", result->listening_count, result->established_count);
    
    return 0;
}

int netstat_listening(netstat_result_t *result)
{
    netstat_connections(result);
    
    printf(COLOR_BOLD COLOR_CYAN "\nLISTENING PORTS\n" COLOR_RESET);
    
    for (int i = 0; i < result->connection_count; i++) {
        if (strstr(result->connections[i].state, "LISTEN") != NULL) {
            printf("  %s %s %s\n", result->connections[i].protocol,
                   result->connections[i].local_address,
                   result->connections[i].state);
        }
    }
    
    return 0;
}

int netstat_process(int pid, netstat_result_t *result)
{
    (void)pid;
    (void)result;
    
    printf(COLOR_BOLD COLOR_CYAN "NETSTAT PROCESS\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "Process-specific netstat requires lsof or ss with process filtering\n" COLOR_RESET);
    return -1;
}

int netstat_route(void)
{
    printf(COLOR_BOLD COLOR_CYAN "ROUTING TABLE\n" COLOR_RESET);
    
#if defined(__APPLE__) || defined(__FreeBSD__)
    system("netstat -rn");
#elif defined(__linux__)
    system("ip route show");
#else
    printf("  Route table not supported on this platform\n");
#endif
    
    return 0;
}

int netstat_interface(const char *iface)
{
    (void)iface;
    
    printf(COLOR_BOLD COLOR_CYAN "INTERFACE STATISTICS\n" COLOR_RESET);
    printf("  Interface: %s\n", iface);
    
#if defined(__APPLE__) || defined(__FreeBSD__)
    char command[256];
    snprintf(command, sizeof(command), "netstat -i %s", iface);
    system(command);
#elif defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "ip -s link show %s", iface);
    system(command);
#else
    printf("  Interface statistics not supported on this platform\n");
#endif
    
    return 0;
}

int netstat_group(const char *group)
{
    (void)group;
    printf(COLOR_BOLD COLOR_CYAN "NETWORK GROUPS\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "Network groups require multicast group support\n" COLOR_RESET);
    return -1;
}

int netstat_timer(void)
{
    printf(COLOR_BOLD COLOR_CYAN "NETWORK TIMERS\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "Network timers require kernel parameter access\n" COLOR_RESET);
    return -1;
}

void print_netstat_results(const netstat_result_t *result)
{
    printf(COLOR_BOLD COLOR_CYAN "\nNETSTAT RESULTS\n" COLOR_RESET);
    printf("  Total connections: %d\n", result->connection_count);
    printf("  TCP: %d, UDP: %d\n", result->tcp_count, result->udp_count);
    printf("  Listening: %d, Established: %d\n\n", result->listening_count, result->established_count);
    
    printf("  Connections:\n");
    for (int i = 0; i < result->connection_count && i < 50; i++) {
        const connection_info_t *conn = &result->connections[i];
        printf("    %s %s %s %s\n", conn->protocol, conn->local_address, 
               conn->remote_address, conn->state);
    }
    
    if (result->connection_count > 50) {
        printf("    ... (%d more connections)\n", result->connection_count - 50);
    }
}
