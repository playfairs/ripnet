# [ripnet](https://ripnet.cc)

Network diagnostics, packet analysis, observability, and authorized load-testing toolkit.

---

## Requirements

- Linux, macOS, or BSD
- gcc
- libpcap
- Meson
- Ninja

## Installation

```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

## Usage

```bash
ripnet --help
```

## Command Families

The CLI is organized around network workflows rather than one-off utilities:

- **Interfaces and capture:** `--list-interfaces`, `--show-stats`, `--capture`
- **Reachability:** `--ping`, `--ping-tcp`, `--ping-udp`, `--ping-sweep`, `--traceroute`, `--traceroute-tcp`, `--traceroute-udp`, `--traceroute-icmp`
- **Scanning:** `--network-scan`, `--scan`, `--udp-scan`, `--syn-scan`, `--fin-scan`, `--xmas-scan`, `--null-scan`, `--service-scan`, `--os-fingerprint`
- **DNS:** `--dns-lookup`, `--dns-reverse`, `--dns-query`, `--dns-server-test`, `--dns-trace`, `--dns-bruteforce`, `--dns-zone-transfer`, `--dnssec-verify`
- **Local network discovery:** `--arp-table`, `--arp-scan`, `--discovery-ping`, `--discovery-arp`, `--discovery-mdns`, `--discovery-llmnr`, `--discovery-netbios`, `--discovery-smb`, `--discovery-upnp`
- **System visibility:** `--netstat`, `--netstat-listening`, `--netstat-route`, `--netstat-process`, `--netstat-interface`, `--route-table`, `--route-get`, `--route-trace`
- **Performance and monitoring:** `--bandwidth-test`, `--bandwidth-speedtest`, `--bandwidth-monitor`, `--bandwidth-history`, `--monitor-start`, `--monitor-status`, `--monitor-log`, `--monitor-export`
- **Service checks:** `--security-ssh`, `--security-http`, `--security-ssl`, `--security-smtp`, `--security-banner`, `--security-dns`, `--security-audit`
- **Controlled load testing:** `--tcp-stress`, `--http-stress`, `--packet-flood`, `--ping-flood`

Examples:

```bash
ripnet --ping example.com --ping-count 5
ripnet --scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet --syn-scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet --dns-query example.com --record-type MX
ripnet --service-scan 192.0.2.10 --port 22
ripnet --security-ssh example.com:22
ripnet --netstat-process 1234
```

Use active scanning, ARP operations, firewall changes, and load-testing modes
only on systems and networks where you have explicit authorization.