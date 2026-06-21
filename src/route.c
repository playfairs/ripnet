#include "ripnet/route.h"
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

int route_table(route_table_t *table)
{
    FILE *fp;
    char line[1024];
    
    memset(table, 0, sizeof(route_table_t));
    
    printf(COLOR_BOLD COLOR_CYAN "ROUTING TABLE\n" COLOR_RESET);
    
#if defined(__linux__)
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not open /proc/net/route\n");
        return -1;
    }
    
    fgets(line, sizeof(line), fp);
    
    while (fgets(line, sizeof(line), fp) != NULL && table->entry_count < 256) {
        route_entry_t *entry = &table->entries[table->entry_count];
        memset(entry, 0, sizeof(route_entry_t));
        
        char iface[32], dest[32], gateway[32], flags[32], metric[32], mask[32];
        unsigned int d, g, m;
        
        if (sscanf(line, "%s %X %X %s %s %s %X", iface, &d, &g, flags, metric, mask, &m) == 7) {
            strncpy(entry->interface, iface, sizeof(entry->interface) - 1);
            
            struct in_addr addr;
            addr.s_addr = d;
            inet_ntop(AF_INET, &addr, entry->destination, sizeof(entry->destination));
            
            addr.s_addr = g;
            inet_ntop(AF_INET, &addr, entry->gateway, sizeof(entry->gateway));
            
            addr.s_addr = m;
            inet_ntop(AF_INET, &addr, entry->netmask, sizeof(entry->netmask));
            
            entry->flags = atoi(flags);
            entry->metric = atoi(metric);
            
            printf("  %s via %s dev %s metric %d\n", 
                   entry->destination, entry->gateway, entry->interface, entry->metric);
            
            table->entry_count++;
        }
    }
    
    fclose(fp);
    
#elif defined(__APPLE__) || defined(__FreeBSD__)
    fp = popen("netstat -rn 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not execute netstat\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL && table->entry_count < 256) {
        if (strstr(line, "Destination") != NULL) continue;
        
        route_entry_t *entry = &table->entries[table->entry_count];
        memset(entry, 0, sizeof(route_entry_t));
        
        char dest[64], gateway[46], flags[32], iface[32];
        if (sscanf(line, "%s %s %s %s", dest, gateway, flags, iface) == 4) {
            strncpy(entry->destination, dest, sizeof(entry->destination) - 1);
            strncpy(entry->gateway, gateway, sizeof(entry->gateway) - 1);
            strncpy(entry->interface, iface, sizeof(entry->interface) - 1);
            entry->flags = atoi(flags);
            
            printf("  %s via %s dev %s\n", entry->destination, entry->gateway, entry->interface);
            table->entry_count++;
        }
    }
    
    pclose(fp);
#else
    fprintf(stderr, "Routing table not supported on this platform\n");
    return -1;
#endif
    
    printf("  Total routes: %d\n", table->entry_count);
    
    return 0;
}

int route_add(const char *destination, const char *gateway, const char *netmask, const char *interface)
{
    printf(COLOR_BOLD COLOR_CYAN "ROUTE ADD\n" COLOR_RESET);
    printf("  Destination: %s, Gateway: %s, Netmask: %s, Interface: %s\n", 
           destination, gateway, netmask, interface);
    
#if defined(__linux__)
    char command[512];
    snprintf(command, sizeof(command), "sudo ip route add %s via %s dev %s", destination, gateway, interface);
    system(command);
    printf("  " COLOR_GREEN "Route added\n" COLOR_RESET);
    return 0;
#elif defined(__APPLE__)
    char command[512];
    snprintf(command, sizeof(command), "sudo route add %s %s %s", destination, gateway, netmask);
    system(command);
    printf("  " COLOR_GREEN "Route added\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Route add not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int route_delete(const char *destination)
{
    printf(COLOR_BOLD COLOR_CYAN "ROUTE DELETE\n" COLOR_RESET);
    printf("  Destination: %s\n", destination);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo ip route del %s", destination);
    system(command);
    printf("  " COLOR_GREEN "Route deleted\n" COLOR_RESET);
    return 0;
#elif defined(__APPLE__)
    char command[256];
    snprintf(command, sizeof(command), "sudo route delete %s", destination);
    system(command);
    printf("  " COLOR_GREEN "Route deleted\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Route delete not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int route_get(const char *destination, route_entry_t *route)
{
    (void)destination;
    (void)route;
    
    printf(COLOR_BOLD COLOR_CYAN "ROUTE GET\n" COLOR_RESET);
    printf("  Destination: %s\n", destination);
    printf("  " COLOR_YELLOW "Route get requires route lookup implementation\n" COLOR_RESET);
    return -1;
}

int route_trace(const char *destination)
{
    printf(COLOR_BOLD COLOR_CYAN "ROUTE TRACE\n" COLOR_RESET);
    printf("  Destination: %s\n", destination);
    printf("  " COLOR_YELLOW "Route trace requires route lookup implementation\n" COLOR_RESET);
    return -1;
}

int route_monitor(void)
{
    printf(COLOR_BOLD COLOR_CYAN "ROUTE MONITOR\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "Route monitor requires continuous monitoring\n" COLOR_RESET);
    return -1;
}

void print_route_table(const route_table_t *table)
{
    printf(COLOR_BOLD COLOR_CYAN "\nROUTING TABLE\n" COLOR_RESET);
    printf("  Total routes: %d\n\n", table->entry_count);
    
    for (int i = 0; i < table->entry_count; i++) {
        const route_entry_t *entry = &table->entries[i];
        printf("  %s via %s dev %s metric %d flags %d\n", 
               entry->destination, entry->gateway, entry->interface, entry->metric, entry->flags);
    }
}
