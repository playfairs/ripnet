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
and libpcap/libcurl linker dependencies. `src/ripnet/buildinfo.d` provides the version
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

environment-dependent.
The test suite includes CLI parsing, malformed/truncated packet parsing,
network CIDR expansion, DNS cache lifecycle, and local HTTP/HTTPS integration
tests for methods, auth, redirects, TLS validation, limits, and bounded batches.
Tests that exercise libpcap, firewall commands, or privileged system interfaces
remain environment-dependent.

Run the complete local regression and HTTP integration suite with:

```bash
nox test
```

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
- **HTTP:** `http-request`, `http-bulk`
- **Controlled load testing:** `tcp-stress`, `http-bulk`

Examples:

```bash
ripnet ping example.com --count 5
ripnet http-request https://example.test/api --method POST --body '{"ok":true}' --json
ripnet http-bulk https://example.test/health --allow-host example.test --count 8 --concurrency 2 --max-rps 4 --json
ripnet ping-sweep 192.0.2.0/30
ripnet scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet network-scan 192.0.2.0/30 --port 443
ripnet syn-scan 192.0.2.10 --start-port 1 --end-port 1024
ripnet dns-query example.com --record-type MX
ripnet service-scan 192.0.2.10 --port 22
ripnet security-ssh example.com --port 22
ripnet netstat-process --pid 1234
ripnet ping example.com --help
```

Use active scanning, ARP operations, firewall changes, and load-testing modes
only on systems and networks where you have explicit authorization.

`monitor-start` and `monitor-stop` currently return an unsupported-operation
error; `monitor-status` performs a one-shot measurement. Successful
`dns-lookup` results are cached in-process for up to 60 seconds, with a limit
of 4,096 entries; failed lookups are not cached. `dns-cache-flush` clears this
process-local cache on every platform. On macOS, it also flushes the system resolver by
running `dscacheutil -flushcache` and signaling `mDNSResponder`; this requires
root, so invoke it as `sudo ripnet dns-cache-flush`. On other platforms, it
clears only ripnet's cache, not the operating system's resolver cache. The
`ddos` command is intentionally unsupported.

`network-scan` currently accepts IPv4 CIDR targets containing at most 4,096
addresses. It excludes network and broadcast addresses for prefixes through
`/30`, and includes all addresses for `/31` and `/32`. It requires `--port`
and attempts TCP connections; an unsuccessful connection does not prove that a
host is offline. `ping-sweep` uses ICMP echo and reports only hosts that
respond, so missing responses are not classified as offline.

`http-request` supports standard/custom token methods, repeated headers and
query parameters, body text/files, basic or bearer authentication, cookies,
proxies, redirects, verified TLS, bounded timeouts, and JSON/raw-file
responses. TLS verification is enabled by default; `--insecure` is an explicit
unsafe opt-in and prints a warning. TRACE requires `--allow-trace`. HTTP/2 is
negotiated over TLS when available; otherwise libcurl falls back. Requests do
not reuse connections.

`http-bulk` is finite-only: exact `--allow-host` matching, redirects disabled,
at most 1,000 requests, 8 workers, 10 requests per second, 16 MiB total
request plus response bodies, and 120 seconds of scheduled duration. It continues after individual failures and
reports per-request results, status distribution, and client-observed latency
percentiles. `--dry-run` validates scope and limits without sending requests.
Continuous-duration/ramp modes, request-definition files, signal-driven
cancellation, server-side telemetry, and persistent connection reuse are not
implemented. `http-stress` returns an unsupported-operation error and directs
users to scoped `http-bulk`; it does not run TCP churn.
