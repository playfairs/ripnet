#include "ripnet/arp.h"
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

int arp_table(arp_table_t *table)
{
    FILE *fp;
    char line[1024];
    
    memset(table, 0, sizeof(arp_table_t));
    
    printf(COLOR_BOLD COLOR_CYAN "ARP TABLE\n" COLOR_RESET);
    
#if defined(__linux__)
    fp = fopen("/proc/net/arp", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not open /proc/net/arp\n");
        return -1;
    }
    
    fgets(line, sizeof(line), fp);
    
    while (fgets(line, sizeof(line), fp) != NULL && table->entry_count < 1024) {
        arp_entry_t *entry = &table->entries[table->entry_count];
        memset(entry, 0, sizeof(arp_entry_t));
        
        char ip[46], mac[18], mask[32], dev[32], flags[32];
        if (sscanf(line, "%s %s %s %s %s %s", ip, mask, flags, mac, mask, dev) == 6) {
            strncpy(entry->ip_address, ip, sizeof(entry->ip_address) - 1);
            strncpy(entry->mac_address, mac, sizeof(entry->mac_address) - 1);
            strncpy(entry->interface, dev, sizeof(entry->interface) - 1);
            entry->permanent = (strstr(flags, "PERM") != NULL);
            
            printf("  %s %s %s %s\n", entry->ip_address, entry->mac_address,
                   entry->interface, entry->permanent ? "(permanent)" : "");
            
            table->entry_count++;
        }
    }
    
    fclose(fp);
    
#elif defined(__APPLE__) || defined(__FreeBSD__)
    fp = popen("arp -an 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not execute arp command\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL && table->entry_count < 1024) {
        arp_entry_t *entry = &table->entries[table->entry_count];
        memset(entry, 0, sizeof(arp_entry_t));
        
        char *question = strchr(line, '?');
        char *at = strchr(line, '@');
        char *on = strchr(line, 'on');
        
        if (question && at && on) {
            strncpy(entry->mac_address, at + 1, 17);
            entry->mac_address[17] = '\0';
            
            char *iface = on + 3;
            strncpy(entry->interface, iface, sizeof(entry->interface) - 1);
            
            char ip_start[46];
            int ip_len = at - question - 2;
            if (ip_len > 0 && ip_len < 45) {
                memcpy(ip_start, question + 2, ip_len);
                ip_start[ip_len] = '\0';
                strncpy(entry->ip_address, ip_start, sizeof(entry->ip_address) - 1);
            }
            
            printf("  %s %s %s\n", entry->ip_address, entry->mac_address, entry->interface);
            table->entry_count++;
        }
    }
    
    pclose(fp);
#else
    fprintf(stderr, "ARP table not supported on this platform\n");
    return -1;
#endif
    
    printf("  Total entries: %d\n", table->entry_count);
    
    return 0;
}

int arp_scan(const char *network, arp_table_t *table)
{
    (void)network;
    (void)table;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP SCAN\n" COLOR_RESET);
    printf("  Network: %s\n", network);
    printf("  " COLOR_YELLOW "ARP scan requires raw socket access\n" COLOR_RESET);
    return -1;
}

int arp_spoof_detect(const char *interface)
{
    (void)interface;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP SPOOF DETECTION\n" COLOR_RESET);
    printf("  Interface: %s\n", interface);
    printf("  " COLOR_YELLOW "ARP spoof detection requires continuous monitoring\n" COLOR_RESET);
    return -1;
}

int arp_request(const char *interface, const char *target_ip)
{
    (void)interface;
    (void)target_ip;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP REQUEST\n" COLOR_RESET);
    printf("  Interface: %s, Target: %s\n", interface, target_ip);
    printf("  " COLOR_YELLOW "ARP request requires raw socket access\n" COLOR_RESET);
    return -1;
}

int arp_reply(const char *interface, const char *target_ip, const char *target_mac)
{
    (void)interface;
    (void)target_ip;
    (void)target_mac;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP REPLY\n" COLOR_RESET);
    printf("  " COLOR_RED "ARP reply injection is a potentially harmful operation\n" COLOR_RESET);
    return -1;
}

int arp_flush(const char *interface)
{
    (void)interface;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP CACHE FLUSH\n" COLOR_RESET);
    
#if defined(__APPLE__)
    system("sudo arp -ad");
    printf("  " COLOR_GREEN "ARP cache flushed\n" COLOR_RESET);
    return 0;
#elif defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo ip neigh flush dev %s", interface);
    system(command);
    printf("  " COLOR_GREEN "ARP cache flushed for %s\n" COLOR_RESET, interface);
    return 0;
#else
    printf("  " COLOR_YELLOW "ARP cache flush not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int arp_cache_add(const char *interface, const char *ip, const char *mac)
{
    (void)interface;
    (void)ip;
    (void)mac;
    
    printf(COLOR_BOLD COLOR_CYAN "ARP CACHE ADD\n" COLOR_RESET);
    printf("  Interface: %s, IP: %s, MAC: %s\n", interface, ip, mac);
    
#if defined(__linux__)
    char command[512];
    snprintf(command, sizeof(command), "sudo arp -s %s %s -i %s", ip, mac, interface);
    system(command);
    printf("  " COLOR_GREEN "ARP entry added\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "ARP cache add not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int arp_cache_delete(const char *ip)
{
    printf(COLOR_BOLD COLOR_CYAN "ARP CACHE DELETE\n" COLOR_RESET);
    printf("  IP: %s\n", ip);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo arp -d %s", ip);
    system(command);
    printf("  " COLOR_GREEN "ARP entry deleted\n" COLOR_RESET);
    return 0;
#elif defined(__APPLE__)
    char command[256];
    snprintf(command, sizeof(command), "sudo arp -d %s", ip);
    system(command);
    printf("  " COLOR_GREEN "ARP entry deleted\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "ARP cache delete not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

void print_arp_table(const arp_table_t *table)
{
    printf(COLOR_BOLD COLOR_CYAN "\nARP TABLE\n" COLOR_RESET);
    printf("  Total entries: %d\n\n", table->entry_count);
    
    for (int i = 0; i < table->entry_count; i++) {
        const arp_entry_t *entry = &table->entries[i];
        printf("  %s %s %s %s\n", entry->ip_address, entry->mac_address,
               entry->interface, entry->permanent ? "(permanent)" : "");
    }
}
