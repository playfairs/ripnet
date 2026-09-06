project(
  'ripnet',
  'c',
  version: run_command('cat', 'VERSION', check: true).stdout().strip(),
  default_options: [
    'c_std=c17',
    'warning_level=3',
  ],
)

version_config = configuration_data()
version_config.set_quoted('RIPNET_VERSION', meson.project_version())
version_header = configure_file(
  output: 'ripnet_version.h',
  configuration: version_config,
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

ripnet_executable = executable(
  'ripnet',
  ripnet_sources,
  include_directories: [
    include_directories('include'),
    include_directories('.'),
  ],
  dependencies: [
    dependency('libpcap'),
    dependency('threads'),
  ],
  install: true,
)

test('cli-help', ripnet_executable, args: ['--help'])
test('network-scan-dispatch', ripnet_executable, args: ['--network-scan', '192.0.2.0/30'])
