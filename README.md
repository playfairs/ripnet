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