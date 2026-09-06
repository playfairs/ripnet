project(
  'ripnet',
  'd',
  version: run_command('cat', 'VERSION', check: true).stdout().strip(),
  default_options: [
    'c_std=c17',
    'warning_level=3',
  ],
)

version_config = configuration_data()
version_config.set_quoted('RIPNET_VERSION', meson.project_version())
version_module = configure_file(
  output: 'buildinfo.d',
  configuration: version_config,
  input: 'src/ripnet/version.d.in',
)

ripnet_sources = files(
  'src/ripnet/app/cli.d',
  'src/ripnet/app/main.d',
  'src/ripnet/model.d',
  'src/ripnet/network/arp.d',
  'src/ripnet/network/capture.d',
  'src/ripnet/network/dns.d',
  'src/ripnet/network/discovery.d',
  'src/ripnet/network/packet.d',
  'src/ripnet/network/probe.d',
  'src/ripnet/network/route.d',
  'src/ripnet/network/scan.d',
  'src/ripnet/network/traceroute.d',
  'src/ripnet/monitoring/bandwidth.d',
  'src/ripnet/monitoring/monitor.d',
  'src/ripnet/monitoring/stats.d',
  'src/ripnet/platform/command.d',
  'src/ripnet/platform/interfaces.d',
  'src/ripnet/security/security.d',
  'src/ripnet/stress/stress.d',
  'src/ripnet/system/firewall.d',
  'src/ripnet/system/netstat.d',
  'src/ripnet/system/process.d',
)
ripnet_sources += version_module

ripnet_executable = executable(
  'ripnet',
  ripnet_sources,
  include_directories: include_directories('src'),
  dependencies: dependency('libpcap'),
  install: true,
)

test('cli-help', ripnet_executable, args: ['--help'])
test('cli-command-help', ripnet_executable, args: ['ping', 'example.com', '--help'])
test('network-scan-dispatch', ripnet_executable, args: ['network-scan', '192.0.2.0/30'])

ripnet_util_tests = executable(
  'ripnet-tests',
  files(
    'src/ripnet/network/packet.d',
    'tests/packet_test.d',
  ),
  include_directories: include_directories('src'),
)

test('packet', ripnet_util_tests)
