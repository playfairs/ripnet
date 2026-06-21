#include "ripnet/stats.h"
#include "ripnet/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>

#if defined(__linux__)
#include <linux/if_link.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <sys/sysctl.h>
#include <net/route.h>
#endif

int list_interfaces(interface_stats_t **stats, int *count)
{
    struct ifaddrs *ifaddr, *ifa;
    interface_stats_t *result = NULL;
    int num_interfaces = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

#if defined(__APPLE__) || defined(__FreeBSD__)
        if (ifa->ifa_addr->sa_family != AF_LINK) {
            continue;
        }
#elif defined(__linux__)
        if (ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }
#endif

        int found = 0;
        for (int i = 0; i < num_interfaces; i++) {
            if (strcmp(result[i].name, ifa->ifa_name) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            num_interfaces++;
            result = xrealloc(result, num_interfaces * sizeof(interface_stats_t));
            memset(&result[num_interfaces - 1], 0, sizeof(interface_stats_t));
            strncpy(result[num_interfaces - 1].name, ifa->ifa_name, 255);
            result[num_interfaces - 1].name[255] = '\0';
            result[num_interfaces - 1].is_up = (ifa->ifa_flags & IFF_UP) != 0;
            result[num_interfaces - 1].is_running = (ifa->ifa_flags & IFF_RUNNING) != 0;

#if defined(__linux__)
            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd >= 0) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
                    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                    snprintf(result[num_interfaces - 1].mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
                if (ioctl(sockfd, SIOCGIFMTU, &ifr) == 0) {
                    result[num_interfaces - 1].mtu = ifr.ifr_mtu;
                }
                close(sockfd);
            }
#elif defined(__APPLE__) || defined(__FreeBSD__)
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_family == AF_LINK && sdl->sdl_alen == 6) {
                unsigned char *mac = (unsigned char *)LLADDR(sdl);
                snprintf(result[num_interfaces - 1].mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            int mib[] = {CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, if_nametoindex(ifa->ifa_name)};
            size_t len;
            sysctl(mib, 6, NULL, &len, NULL, 0);
            char *buf = xmalloc(len);
            if (sysctl(mib, 6, buf, &len, NULL, 0) == 0) {
                struct if_msghdr *ifm = (struct if_msghdr *)buf;
                result[num_interfaces - 1].mtu = ifm->ifm_data.ifi_mtu;
            }
            free(buf);
#endif
        }
    }

    freeifaddrs(ifaddr);

    for (int i = 0; i < num_interfaces; i++) {
        get_interface_stats(result[i].name, &result[i]);
    }

    *stats = result;
    *count = num_interfaces;
    return 0;
}

int get_interface_stats(const char *iface, interface_stats_t *stats)
{
#if defined(__linux__)
    char path[256];
    FILE *fp;

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->rx_packets);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->tx_packets);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->rx_bytes);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->tx_bytes);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_errors", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->rx_errors);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_errors", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->tx_errors);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_dropped", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->rx_dropped);
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_dropped", iface);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%lu", &stats->tx_dropped);
        fclose(fp);
    }

#elif defined(__APPLE__) || defined(__FreeBSD__)
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, if_nametoindex(iface)};
    size_t len;
    sysctl(mib, 6, NULL, &len, NULL, 0);
    char *buf = xmalloc(len);
    if (sysctl(mib, 6, buf, &len, NULL, 0) == 0) {
        struct if_msghdr *ifm = (struct if_msghdr *)buf;
        stats->rx_packets = ifm->ifm_data.ifi_ipackets;
        stats->tx_packets = ifm->ifm_data.ifi_opackets;
        stats->rx_bytes = ifm->ifm_data.ifi_ibytes;
        stats->tx_bytes = ifm->ifm_data.ifi_obytes;
        stats->rx_errors = ifm->ifm_data.ifi_ierrors;
        stats->tx_errors = ifm->ifm_data.ifi_oerrors;
        stats->rx_dropped = ifm->ifm_data.ifi_iqdrops;
        stats->tx_dropped = 0;
    }
    free(buf);
#endif

    return 0;
}

void print_interface_stats(const interface_stats_t *stats)
{
    char rx_buf[32], tx_buf[32];
    format_bytes(stats->rx_bytes, rx_buf, sizeof(rx_buf));
    format_bytes(stats->tx_bytes, tx_buf, sizeof(tx_buf));

    printf("Interface: %s\n", stats->name);
    printf("  Status: %s, %s\n", stats->is_up ? "UP" : "DOWN", stats->is_running ? "RUNNING" : "NOT RUNNING");
    printf("  MAC: %s\n", stats->mac_addr);
    printf("  MTU: %u\n", stats->mtu);
    printf("  RX: %" PRIu64 " packets (%s), %" PRIu64 " errors, %" PRIu64 " dropped\n", stats->rx_packets, rx_buf, stats->rx_errors, stats->rx_dropped);
    printf("  TX: %" PRIu64 " packets (%s), %" PRIu64 " errors, %" PRIu64 " dropped\n", stats->tx_packets, tx_buf, stats->tx_errors, stats->tx_dropped);
}

void free_interface_stats(interface_stats_t *stats, int count)
{
    (void)count;
    free(stats);
}