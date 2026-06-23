#ifndef RIPNET_ROUTE_H
#define RIPNET_ROUTE_H

#include <stdint.h>

typedef struct {
    char destination[64];
    char gateway[46];
    char netmask[46];
    char interface[32];
    int metric;
    int flags;
} route_entry_t;

typedef struct {
    route_entry_t entries[64];
    int entry_count;
} route_table_t;

int route_table(route_table_t *table);
int route_add(const char *destination, const char *gateway, const char *netmask, const char *interface);
int route_delete(const char *destination);
int route_get(const char *destination, route_entry_t *route);
int route_trace(const char *destination);
int route_monitor(void);
void print_route_table(const route_table_t *table);

#endif
