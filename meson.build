project(
  'ripnet',
  'c',
  version: import('fs').read('VERSION').strip(),
  default_options: [
    'c_std=c17',
    'warning_level=3',
  ],
)

ripnet_sources = files(
  'src/arp.c',
  'src/bandwidth.c',
  'src/cli.c',
  'src/discovery.c',
  'src/dns.c',
  'src/firewall.c',
  'src/main.c',
  'src/monitor.c',
  'src/netstat.c',
  'src/packet.c',
  'src/ping.c',
  'src/process.c',
  'src/route.c',
  'src/scan.c',
  'src/security.c',
  'src/stats.c',
  'src/stress.c',
  'src/traceroute.c',
  'src/util.c',
)

add_project_arguments(
  '-D_BSD_SOURCE',
  '-D_DEFAULT_SOURCE',
  '-D__FAVOR_BSD',
  '-D_GNU_SOURCE',
  language: 'c',
)

executable(
  'ripnet',
  ripnet_sources,
  include_directories: include_directories('include'),
  dependencies: [
    dependency('libpcap'),
    dependency('threads'),
  ],
  install: true,
)
