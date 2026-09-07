# [ripnet](https://ripnet.cc)

Network diagnostics, packet analysis, observability, and authorized load-testing toolkit.

---

## Requirements

- Linux, macOS, or BSD
- an LLVM D compiler (`ldc2`)
- libpcap
- Nox

## Installation

```bash
nox setup build
nox build build -j8
sudo nox install
```

## Usage

```bash
ripnet --help
```

## Development

The primary build system is Nox. The repository also provides a Nix
development shell with the D toolchain used by the build:

```bash
nix develop
nox setup build
nox build build -j8
nox install --prefix "$HOME/.local"
```

The `nox.build` file declares the D executable, source graph, project metadata,
and libpcap linker dependency. `src/ripnet/buildinfo.d` provides the version
module consumed by the application and is kept in sync with `VERSION`.

The implementation is organized as D modules by responsibility:

- `src/ripnet/app`: argument parsing and command dispatch
- `src/ripnet/network`: DNS, probes, scans, routes, ARP, discovery, packet
  parsing, traceroute, and libpcap capture
- `src/ripnet/system`: firewall, netstat, and process adapters
- `src/ripnet/monitoring`: interface counters, bandwidth, and monitor state

- `src/ripnet/security` and `src/ripnet/stress`: higher-level checks and load
  testing
- `src/ripnet/platform`: OS command and interface adapters

There are no C or C++ implementation files in the application. The only
native interoperability boundary is the small `extern(C)` declaration set in
`src/ripnet/network/capture.d`, which calls the third-party libpcap library.
The rest of the application, including packet parsing and CLI behavior, is
implemented in D.

The test suite includes CLI smoke tests and malformed/truncated packet parser
tests. Tests that exercise libpcap, firewall commands, or privileged system
interfaces remain environment-dependent.

## Command Families

The CLI is organized around network workflows rather than one-off utilities:

- **Interfaces and capture:** `list-interfaces`, `show-stats`, `capture`
- **Reachability:** `ping`, `ping-tcp`, `ping-udp`, `ping-sweep`, `traceroute`, `traceroute-tcp`, `traceroute-udp`, `traceroute-icmp`
- **Scanning:** `network-scan`, `scan`, `udp-scan`, `syn-scan`, `fin-scan`, `xmas-scan`, `null-scan`, `service-scan`, `os-fingerprint`
- **DNS:** `dns-lookup`, `dns-reverse`, `dns-query`, `dns-server-test`, `dns-trace`, `dns-bruteforce`, `dns-zone-transfer`, `dnssec-verify`
- **Local network discovery:** `arp-table`, `arp-scan`, `discovery-ping`, `discovery-arp`, `discovery-mdns`, `discovery-llmnr`, `discovery-netbios`, `discovery-smb`, `discovery-upnp`
- **System visibility:** `netstat`, `netstat-listening`, `netstat-route`, `netstat-process`, `netstat-interface`, `route-table`, `route-get`, `route-trace`
- **Performance and monitoring:** `bandwidth-test`, `bandwidth-speedtest`, `bandwidth-monitor`, `bandwidth-history`, `monitor-start`, `monitor-status`, `monitor-log`, `monitor-export`
- **Service checks:** `security-ssh`, `security-http`, `security-ssl`, `security-smtp`, `security-banner`, `security-dns`, `security-audit`
- **Controlled load testing:** `tcp-stress`, `http-stress`, `packet-flood`, `ping-flood`

Examples:

```bash
ripnet ping example.com --count 5
ripnet scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet syn-scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet dns-query example.com --record-type MX
ripnet service-scan 192.0.2.10 --port 22
ripnet security-ssh example.com --port 22
ripnet netstat-process --pid 1234
ripnet ping example.com --help
```

Use active scanning, ARP operations, firewall changes, and load-testing modes
only on systems and networks where you have explicit authorization.
