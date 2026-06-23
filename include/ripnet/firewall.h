#ifndef RIPNET_FIREWALL_H
#define RIPNET_FIREWALL_H

#include <stdint.h>

typedef struct {
    char chain[64];
    int rule_num;
    char packets[32];
    char bytes[32];
    char target[64];
    char protocol[16];
    char source[64];
    char destination[64];
    char source_port[32];
    char destination_port[32];
    char options[256];
} firewall_rule_t;

typedef struct {
    firewall_rule_t rules[256];
    int rule_count;
} firewall_ruleset_t;

int firewall_list(firewall_ruleset_t *ruleset);
int firewall_add(const char *chain, const char *rule);
int firewall_delete(const char *chain, int rule_num);
int firewall_flush(const char *chain);
int firewall_status(void);
int firewall_log(int enable);
int firewall_block_ip(const char *ip);
int firewall_unblock_ip(const char *ip);
int firewall_block_port(int port, const char *protocol);
int firewall_unblock_port(int port, const char *protocol);
void print_firewall_rules(const firewall_ruleset_t *ruleset);

#endif
