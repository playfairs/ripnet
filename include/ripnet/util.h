#ifndef RIPNET_UTIL_H
#define RIPNET_UTIL_H

#include <stddef.h>
#include <stdint.h>

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);
void timestamp_now(char *buf, size_t len);
int parse_uint(const char *s, unsigned int *val);
int parse_ulong(const char *s, unsigned long *val);
void format_bytes(uint64_t bytes, char *buf, size_t len);
void format_rate(uint64_t rate, char *buf, size_t len);

#endif