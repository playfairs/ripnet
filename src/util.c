#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        exit(1);
    }
    return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (!ptr) {
        fprintf(stderr, "calloc failed: %s\n", strerror(errno));
        exit(1);
    }
    return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        fprintf(stderr, "realloc failed: %s\n", strerror(errno));
        exit(1);
    }
    return new_ptr;
}

char *xstrdup(const char *s)
{
    char *dup = strdup(s);
    if (!dup) {
        fprintf(stderr, "strdup failed: %s\n", strerror(errno));
        exit(1);
    }
    return dup;
}

void timestamp_now(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

int parse_uint(const char *s, unsigned int *val)
{
    char *endptr;
    unsigned long result = strtoul(s, &endptr, 10);
    if (*endptr != '\0' || result > UINT_MAX) {
        return -1;
    }
    *val = (unsigned int)result;
    return 0;
}

int parse_ulong(const char *s, unsigned long *val)
{
    char *endptr;
    *val = strtoul(s, &endptr, 10);
    if (*endptr != '\0') {
        return -1;
    }
    return 0;
}

void format_bytes(uint64_t bytes, char *buf, size_t len)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double value = (double)bytes;

    while (value >= 1024.0 && unit_index < 4) {
        value /= 1024.0;
        unit_index++;
    }

    snprintf(buf, len, "%.2f %s", value, units[unit_index]);
}

void format_rate(uint64_t rate, char *buf, size_t len)
{
    const char *units[] = {"bps", "Kbps", "Mbps", "Gbps"};
    int unit_index = 0;
    double value = (double)rate;

    while (value >= 1000.0 && unit_index < 3) {
        value /= 1000.0;
        unit_index++;
    }

    snprintf(buf, len, "%.2f %s", value, units[unit_index]);
}