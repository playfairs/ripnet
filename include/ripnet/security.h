#ifndef RIPNET_SECURITY_H
#define RIPNET_SECURITY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char vulnerability_id[64];
    char severity[32];
    char description[512];
    char affected_service[128];
    char cve_id[64];
    double cvss_score;
    char remediation[512];
} vulnerability_t;

typedef struct {
    vulnerability_t vulnerabilities[1024];
    int vulnerability_count;
    char target[256];
    int scan_time_sec;
} security_scan_result_t;

int security_scan(const char *target, security_scan_result_t *result);
int security_audit(const char *target);
int security_ssl_check(const char *hostname, int port);
int security_ssh_check(const char *hostname, int port);
int security_http_check(const char *hostname, int port);
int security_smtp_check(const char *hostname, int port);
int security_dns_check(const char *dns_server);
int security_mitm_detect(const char *interface);
int security_port_knocking(const char *target, int *ports, int port_count);
int security_honeypot_detect(const char *target);
int security_banner_grab(const char *target, int port, char *banner, size_t banner_len);
void print_security_results(const security_scan_result_t *result);

#endif
