#include "ripnet/process.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

int scan_network_processes(const char *process_filter, int pid_filter)
{
    char command[1024];
    FILE *fp;
    char line[1024];
    int found = 0;
    int tcp_count = 0;
    int udp_count = 0;
    int listen_count = 0;
    int established_count = 0;

    printf(COLOR_BOLD COLOR_CYAN "NETWORK PROCESS SCANNER\n" COLOR_RESET);
    printf("\n");

    if (pid_filter > 0) {
        printf(COLOR_RESET "Filtering by PID: " COLOR_BOLD COLOR_GREEN "%d\n", pid_filter);
    }
    if (strlen(process_filter) > 0) {
        printf(COLOR_RESET "Filtering by Process: " COLOR_BOLD COLOR_GREEN "%s\n", process_filter);
    }
    printf("\n");

#if defined(__APPLE__) || defined(__FreeBSD__)
    snprintf(command, sizeof(command), "lsof -i -P -n 2>/dev/null");
#elif defined(__linux__)
    snprintf(command, sizeof(command), "ss -tunp 2>/dev/null");
#else
    fprintf(stderr, "Process scanning not supported on this platform\n");
    return -1;
#endif

    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to execute network process scanner\n");
        return -1;
    }

    typedef struct {
        char pid[32];
        char name[256];
        char proto[32];
        char local[256];
        char remote[256];
        char state[64];
    } conn_info_t;

    conn_info_t connections[1024];
    int conn_count = 0;

    while (fgets(line, sizeof(line), fp) != NULL && conn_count < 1024) {
        conn_info_t *conn = &connections[conn_count];
        memset(conn, 0, sizeof(conn_info_t));

#if defined(__APPLE__) || defined(__FreeBSD__)
        if (strstr(line, "COMMAND") != NULL || strstr(line, "NAME") != NULL) {
            continue;
        }

        char *token = strtok(line, " \t");
        if (token == NULL) continue;

        strncpy(conn->name, token, sizeof(conn->name) - 1);

        token = strtok(NULL, " \t");
        if (token == NULL) continue;
        strncpy(conn->pid, token, sizeof(conn->pid) - 1);

        for (int i = 0; i < 5; i++) {
            token = strtok(NULL, " \t");
            if (token == NULL) break;
        }

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->proto, token, sizeof(conn->proto) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->local, token, sizeof(conn->local) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->remote, token, sizeof(conn->remote) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->state, token, sizeof(conn->state) - 1);

#elif defined(__linux__)
        if (strstr(line, "Netid") != NULL || strstr(line, "State") != NULL) {
            continue;
        }

        char *token = strtok(line, " \t");
        if (token == NULL) continue;
        strncpy(conn->proto, token, sizeof(conn->proto) - 1);

        for (int i = 0; i < 4; i++) {
            token = strtok(NULL, " \t");
            if (token == NULL) break;
        }

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->local, token, sizeof(conn->local) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->remote, token, sizeof(conn->remote) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->state, token, sizeof(conn->state) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->pid, token, sizeof(conn->pid) - 1);

        token = strtok(NULL, " \t");
        if (token != NULL) strncpy(conn->name, token, sizeof(conn->name) - 1);
#endif

        int match = 1;
        if (pid_filter > 0 && atoi(conn->pid) != pid_filter) {
            match = 0;
        }
        if (strlen(process_filter) > 0 && strstr(conn->name, process_filter) == NULL) {
            match = 0;
        }

        if (match && strlen(conn->pid) > 0) {
            conn_count++;
            found++;
        }
    }

    pclose(fp);

    if (found == 0) {
        printf(COLOR_YELLOW "No matching network processes found\n" COLOR_RESET);
        return 0;
    }

    for (int i = 0; i < conn_count; i++) {
        if (strcmp(connections[i].proto, "TCP") == 0) tcp_count++;
        if (strcmp(connections[i].proto, "UDP") == 0) udp_count++;
        if (strstr(connections[i].state, "LISTEN") != NULL) listen_count++;
        if (strstr(connections[i].state, "ESTABLISHED") != NULL) established_count++;
    }

    printf(COLOR_BOLD COLOR_CYAN "┌─ " COLOR_GREEN "%s" COLOR_RESET COLOR_CYAN " (PID: " COLOR_YELLOW "%s" COLOR_RESET COLOR_CYAN ")\n", connections[0].name, connections[0].pid);
    printf("│\n");
    printf("├─ " COLOR_BOLD "Statistics\n" COLOR_RESET);
    printf("│   Total Connections: " COLOR_GREEN "%d\n" COLOR_RESET, conn_count);
    printf("│   TCP: " COLOR_GREEN "%d" COLOR_RESET " | UDP: " COLOR_GREEN "%d\n" COLOR_RESET, tcp_count, udp_count);
    printf("│   Listening: " COLOR_GREEN "%d" COLOR_RESET " | Established: " COLOR_GREEN "%d\n" COLOR_RESET, listen_count, established_count);
    printf("│\n");
    printf("├─ " COLOR_BOLD "Network Graph\n" COLOR_RESET);

    for (int i = 0; i < conn_count; i++) {
        conn_info_t *conn = &connections[i];
        char *color = strcmp(conn->proto, "TCP") == 0 ? COLOR_BLUE : COLOR_MAGENTA;

        if (i == conn_count - 1) {
            printf("└── ");
        } else {
            printf("├── ");
        }

        printf("%s%s" COLOR_RESET " %s", color, conn->proto, conn->local);

        if (strlen(conn->remote) > 0 && strcmp(conn->remote, "*:*") != 0) {
            printf(" → %s", conn->remote);
        }

        if (strlen(conn->state) > 0) {
            printf(" [%s]", conn->state);
        }

        printf("\n");
    }

    printf("\n" COLOR_BOLD "Total: " COLOR_GREEN "%d connections\n" COLOR_RESET, conn_count);

    return 0;
}
