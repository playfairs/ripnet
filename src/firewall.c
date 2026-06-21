#include "ripnet/firewall.h"
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

int firewall_list(firewall_ruleset_t *ruleset)
{
    FILE *fp;
    char line[1024];
    
    memset(ruleset, 0, sizeof(firewall_ruleset_t));
    
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL RULES\n" COLOR_RESET);
    
#if defined(__linux__)
    fp = popen("sudo iptables -L -n -v 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not execute iptables\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL && ruleset->rule_count < 1024) {
        if (strstr(line, "Chain") != NULL || strstr(line, "target") != NULL) {
            continue;
        }
        
        firewall_rule_t *rule = &ruleset->rules[ruleset->rule_count];
        memset(rule, 0, sizeof(firewall_rule_t));
        
        char pkts[32], bytes[32], target[64], prot[16], opt[32], in[32], out[32], 
             source[64], destination[64], opts[256];
        
        if (sscanf(line, "%s %s %s %s %s %s %s %s %s %s", pkts, bytes, target, prot, 
                   opt, in, out, source, destination, opts) >= 5) {
            strncpy(rule->packets, pkts, sizeof(rule->packets) - 1);
            strncpy(rule->bytes, bytes, sizeof(rule->bytes) - 1);
            strncpy(rule->target, target, sizeof(rule->target) - 1);
            strncpy(rule->protocol, prot, sizeof(rule->protocol) - 1);
            strncpy(rule->source, source, sizeof(rule->source) - 1);
            strncpy(rule->destination, destination, sizeof(rule->destination) - 1);
            strncpy(rule->options, opts, sizeof(rule->options) - 1);
            
            printf("  %s %s %s %s %s\n", rule->target, rule->protocol, 
                   rule->source, rule->destination, rule->options);
            
            ruleset->rule_count++;
        }
    }
    
    pclose(fp);
    
#elif defined(__APPLE__)
    fp = popen("sudo pfctl -s rules 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not execute pfctl\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp) != NULL && ruleset->rule_count < 1024) {
        firewall_rule_t *rule = &ruleset->rules[ruleset->rule_count];
        memset(rule, 0, sizeof(firewall_rule_t));
        
        strncpy(rule->options, line, sizeof(rule->options) - 1);
        printf("  %s", line);
        
        ruleset->rule_count++;
    }
    
    pclose(fp);
#else
    fprintf(stderr, "Firewall not supported on this platform\n");
    return -1;
#endif
    
    printf("  Total rules: %d\n", ruleset->rule_count);
    
    return 0;
}

int firewall_add(const char *chain, const char *rule)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL ADD\n" COLOR_RESET);
    printf("  Chain: %s, Rule: %s\n", chain, rule);
    
#if defined(__linux__)
    char command[512];
    snprintf(command, sizeof(command), "sudo iptables -A %s %s", chain, rule);
    system(command);
    printf("  " COLOR_GREEN "Rule added\n" COLOR_RESET);
    return 0;
#elif defined(__APPLE__)
    printf("  " COLOR_YELLOW "Use pfctl to add rules on macOS\n" COLOR_RESET);
    return -1;
#else
    printf("  " COLOR_YELLOW "Firewall add not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_delete(const char *chain, int rule_num)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL DELETE\n" COLOR_RESET);
    printf("  Chain: %s, Rule: %d\n", chain, rule_num);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -D %s %d", chain, rule_num);
    system(command);
    printf("  " COLOR_GREEN "Rule deleted\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Firewall delete not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_flush(const char *chain)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL FLUSH\n" COLOR_RESET);
    printf("  Chain: %s\n", chain);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -F %s", chain);
    system(command);
    printf("  " COLOR_GREEN "Chain flushed\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Firewall flush not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_status(void)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL STATUS\n" COLOR_RESET);
    
#if defined(__linux__)
    system("sudo iptables -L -n -v | head -20");
#elif defined(__APPLE__)
    system("sudo pfctl -s info");
#else
    printf("  " COLOR_YELLOW "Firewall status not supported on this platform\n" COLOR_RESET);
#endif
    
    return 0;
}

int firewall_log(int enable)
{
    (void)enable;
    
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL LOG\n" COLOR_RESET);
    printf("  " COLOR_YELLOW "Firewall logging requires specific configuration\n" COLOR_RESET);
    return -1;
}

int firewall_block_ip(const char *ip)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL BLOCK IP\n" COLOR_RESET);
    printf("  IP: %s\n", ip);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -s %s -j DROP", ip);
    system(command);
    printf("  " COLOR_GREEN "IP blocked\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "IP blocking not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_unblock_ip(const char *ip)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL UNBLOCK IP\n" COLOR_RESET);
    printf("  IP: %s\n", ip);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -D INPUT -s %s -j DROP", ip);
    system(command);
    printf("  " COLOR_GREEN "IP unblocked\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "IP unblocking not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_block_port(int port, const char *protocol)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL BLOCK PORT\n" COLOR_RESET);
    printf("  Port: %d, Protocol: %s\n", port, protocol);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -p %s --dport %d -j DROP", protocol, port);
    system(command);
    printf("  " COLOR_GREEN "Port blocked\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Port blocking not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

int firewall_unblock_port(int port, const char *protocol)
{
    printf(COLOR_BOLD COLOR_CYAN "FIREWALL UNBLOCK PORT\n" COLOR_RESET);
    printf("  Port: %d, Protocol: %s\n", port, protocol);
    
#if defined(__linux__)
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -D INPUT -p %s --dport %d -j DROP", protocol, port);
    system(command);
    printf("  " COLOR_GREEN "Port unblocked\n" COLOR_RESET);
    return 0;
#else
    printf("  " COLOR_YELLOW "Port unblocking not supported on this platform\n" COLOR_RESET);
    return -1;
#endif
}

void print_firewall_rules(const firewall_ruleset_t *ruleset)
{
    printf(COLOR_BOLD COLOR_CYAN "\nFIREWALL RULES\n" COLOR_RESET);
    printf("  Total rules: %d\n\n", ruleset->rule_count);
    
    for (int i = 0; i < ruleset->rule_count; i++) {
        const firewall_rule_t *rule = &ruleset->rules[i];
        printf("  %s %s %s %s %s %s\n", rule->target, rule->protocol, 
               rule->source, rule->destination, rule->source_port, rule->destination_port);
    }
}
