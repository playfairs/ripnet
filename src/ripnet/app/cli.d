module ripnet.app.cli;

import ripnet.model;
import std.algorithm : canFind;
import std.conv : to;
import std.string : startsWith, split, strip, indexOf;

public struct ParseResult
{
    CliOptions options;
    string error;
    bool ok;
}

private Command[string] commands()
{
    Command[string] result;
    result["help"] = Command.help;
    result["version"] = Command.showVersion;
    result["list-interfaces"] = Command.listInterfaces;
    result["show-stats"] = Command.showStats;
    result["capture"] = Command.capture;
    result["ping"] = Command.ping;
    result["ping-tcp"] = Command.pingTcp;
    result["ping-udp"] = Command.pingUdp;
    result["ping-sweep"] = Command.pingSweep;
    result["traceroute"] = Command.traceroute;
    result["traceroute-tcp"] = Command.tracerouteTcp;
    result["traceroute-udp"] = Command.tracerouteUdp;
    result["traceroute-icmp"] = Command.tracerouteIcmp;
    result["port-scan"] = Command.portScan;
    result["scan"] = Command.scan;
    result["service-scan"] = Command.serviceScan;
    result["os-fingerprint"] = Command.osFingerprint;
    result["vuln-scan"] = Command.vulnerabilityScan;
    result["network-scan"] = Command.networkScan;
    result["udp-scan"] = Command.udpScan;
    result["syn-scan"] = Command.synScan;
    result["fin-scan"] = Command.finScan;
    result["xmas-scan"] = Command.xmasScan;
    result["null-scan"] = Command.nullScan;
    result["dns-lookup"] = Command.dnsLookup;
    result["dns-reverse"] = Command.dnsReverse;
    result["dns-query"] = Command.dnsQuery;
    result["dns-server-test"] = Command.dnsServerTest;
    result["dns-trace"] = Command.dnsTrace;
    result["dns-bruteforce"] = Command.dnsBruteforce;
    result["dns-zone-transfer"] = Command.dnsZoneTransfer;
    result["dnssec-verify"] = Command.dnssecVerify;
    result["dns-cache-flush"] = Command.dnsCacheFlush;
    result["arp-table"] = Command.arpTable;
    result["arp-scan"] = Command.arpScan;
    result["arp-spoof-detect"] = Command.arpSpoofDetect;
    result["arp-request"] = Command.arpRequest;
    result["arp-reply"] = Command.arpReply;
    result["arp-cache-add"] = Command.arpCacheAdd;
    result["arp-cache-delete"] = Command.arpCacheDelete;
    result["discovery-ping"] = Command.discoveryPing;
    result["discovery-arp"] = Command.discoveryArp;
    result["discovery-dns"] = Command.discoveryDns;
    result["discovery-snmp"] = Command.discoverySnmp;
    result["discovery-upnp"] = Command.discoveryUpnp;
    result["discovery-mdns"] = Command.discoveryMdns;
    result["discovery-llmnr"] = Command.discoveryLlmnr;
    result["discovery-netbios"] = Command.discoveryNetbios;
    result["discovery-smb"] = Command.discoverySmb;
    result["discovery-http"] = Command.discoveryHttp;
    result["discovery-ssl"] = Command.discoverySsl;
    result["netstat"] = Command.netstat;
    result["netstat-listening"] = Command.netstatListening;
    result["netstat-route"] = Command.netstatRoute;
    result["netstat-process"] = Command.netstatProcess;
    result["netstat-interface"] = Command.netstatInterface;
    result["netstat-group"] = Command.netstatGroup;
    result["netstat-timer"] = Command.netstatTimer;
    result["scan-processes"] = Command.scanProcesses;
    result["route-table"] = Command.routeTable;
    result["route-get"] = Command.routeGet;
    result["route-trace"] = Command.routeTrace;
    result["route-monitor"] = Command.routeMonitor;
    result["firewall-status"] = Command.firewallStatus;
    result["firewall-log"] = Command.firewallLog;
    result["firewall-add"] = Command.firewallAdd;
    result["firewall-delete"] = Command.firewallDelete;
    result["firewall-flush"] = Command.firewallFlush;
    result["block-ip"] = Command.blockIp;
    result["unblock-ip"] = Command.unblockIp;
    result["block-port"] = Command.blockPort;
    result["unblock-port"] = Command.unblockPort;
    result["bandwidth-test"] = Command.bandwidthTest;
    result["bandwidth-speedtest"] = Command.bandwidthSpeedtest;
    result["bandwidth-monitor"] = Command.bandwidthMonitor;
    result["bandwidth-history"] = Command.bandwidthHistory;
    result["bandwidth-limit"] = Command.bandwidthLimit;
    result["bandwidth-shaper"] = Command.bandwidthShaper;
    result["monitor-start"] = Command.monitorStart;
    result["monitor-stop"] = Command.monitorStop;
    result["monitor-status"] = Command.monitorStatus;
    result["monitor-alert"] = Command.monitorAlert;
    result["monitor-log"] = Command.monitorLog;
    result["monitor-export"] = Command.monitorExport;
    result["security-ssh"] = Command.securitySsh;
    result["ssh"] = Command.securitySsh;
    result["sftp"] = Command.sftp;
    result["security-http"] = Command.securityHttp;
    result["security-ssl"] = Command.securitySsl;
    result["security-smtp"] = Command.securitySmtp;
    result["security-banner"] = Command.securityBanner;
    result["security-dns"] = Command.securityDns;
    result["security-audit"] = Command.securityAudit;
    result["security-scan"] = Command.securityScan;
    result["tcp-stress"] = Command.tcpStress;
    result["http-stress"] = Command.httpStress;
    result["packet-flood"] = Command.packetFlood;
    result["ping-flood"] = Command.pingFlood;
    result["port-knocking"] = Command.portKnocking;
    result["ddos"] = Command.ddos;
    return result;
}

private bool needsValue(string key)
{
    return [
        "interface", "filter", "host", "hostname", "user", "identity", "command",
        "jump-host", "local-forward", "remote-forward", "dynamic-forward",
        "proxy-command", "ssh-option", "remote-path",
        "network", "domain",
        "dns-server", "record-type", "wordlist", "ip", "mac", "protocol", "chain",
        "rule", "log", "export", "process", "path", "port", "start-port",
        "end-port", "count", "timeout", "concurrency", "duration", "interval",
        "rate-limit", "max-bps", "download-bps", "upload-bps", "pid", "threshold"
    ].canFind(key);
}

private string canonicalOption(string option)
{
    switch (option)
    {
    case "h": return "help";
    case "v": return "version";
    case "V": return "verbose";
    case "j": return "json";
    case "i": return "interface";
    case "f": return "filter";
    case "H": return "host";
    case "N": return "hostname";
    case "u": return "user";
    case "A": return "agent-forwarding";
    case "X": return "x11-forwarding";
    case "T": return "no-tty";
    case "J": return "jump-host";
    case "n": return "network";
    case "d": return "domain";
    case "s": return "dns-server";
    case "r": return "record-type";
    case "w": return "wordlist";
    case "I": return "ip";
    case "m": return "mac";
    case "P": return "protocol";
    case "C": return "chain";
    case "R": return "rule";
    case "l": return "log";
    case "e": return "export";
    case "q": return "process";
    case "x": return "path";
    case "p": return "port";
    case "sp": return "start-port";
    case "ep": return "end-port";
    case "c": return "count";
    case "t": return "timeout";
    case "k": return "concurrency";
    case "du": return "duration";
    case "int": return "interval";
    case "rl": return "rate-limit";
    case "mb": return "max-bps";
    case "db": return "download-bps";
    case "ub": return "upload-bps";
    case "pid": return "pid";
    case "th": return "threshold";
    default: return option;
    }
}

public ParseResult parseArgs(string[] args)
{
    CliOptions options;
    auto known = commands;
    string[] positional;
    bool endOfOptions;
    for (size_t index = 1; index < args.length; ++index)
    {
        auto token = args[index];
        if (token == "--")
        {
            endOfOptions = true;
            continue;
        }
        if (endOfOptions || (token.length < 2 || token[0] != '-'))
        {
            if (!positional.length && token in known)
            {
                options.command = known[token];
                continue;
            }
            positional ~= token;
            continue;
        }
        auto option = token.startsWith("--") ? token[2 .. $] : token[1 .. $];
        string value;
        auto equals = option.indexOf('=');
        if (equals >= 0)
        {
            value = option[equals + 1 .. $];
            option = option[0 .. equals];
        }
        auto originalOption = option;
        option = canonicalOption(option);
        if (!token.startsWith("--") && option == "version" && originalOption != "v")
            return ParseResult(options, "use --version or -v to show the version", false);
        if (option == "help")
        {
            options.showHelp = true;
            continue;
        }
        if (option == "version")
        {
            options.command = Command.showVersion;
            continue;
        }
        if (option == "json")
        {
            options.json = true;
            continue;
        }
        if (option == "verbose")
        {
            options.verbose = true;
            continue;
        }
        if (option == "promisc")
        {
            options.promisc = true;
            continue;
        }
        if (option == "agent-forwarding")
        {
            options.sshAgentForwarding = true;
            continue;
        }
        if (option == "x11-forwarding")
        {
            options.sshX11Forwarding = true;
            continue;
        }
        if (option == "no-tty")
        {
            options.sshNoTty = true;
            continue;
        }
        if (!needsValue(option))
            return ParseResult(options, "unknown option -" ~ originalOption, false);
        if (value.length == 0 && index + 1 < args.length)
            value = args[++index];
        if (value.length == 0)
            return ParseResult(options, "missing value for --" ~ option, false);
        auto error = assign(options, option, value);
        if (error.length)
            return ParseResult(options, error, false);
    }
    options.positional = positional;
    if (!options.host.length && positional.length)
        options.host = positional[0];
    if ((options.command == Command.discoveryPing) && !options.network.length
            && positional.length)
        options.network = positional[0];
    if ((options.command == Command.discoveryDns
            || options.command == Command.dnsBruteforce)
            && !options.domain.length && positional.length)
        options.domain = positional[0];
    if (options.command == Command.sftp && !options.sftpRemotePath
            && positional.length > 1)
        options.sftpRemotePath = positional[1];
    if (!options.hostname.length)
        options.hostname = options.host;
    return ParseResult(options, "", true);
}

private string assign(ref CliOptions options, string key, string value)
{
    try
    {
        switch (key)
        {
        case "interface":
            options.interfaceName = value;
            break;
        case "filter":
            options.filter = value;
            break;
        case "host":
            options.host = value;
            break;
        case "hostname":
            options.hostname = value;
            break;
        case "user":
            options.sshUser = value;
            break;
        case "identity":
            options.sshIdentity = value;
            break;
        case "command":
            options.sshCommand = value;
            break;
        case "jump-host":
            options.sshJumpHost = value;
            break;
        case "local-forward":
            options.sshLocalForward = value;
            break;
        case "remote-forward":
            options.sshRemoteForward = value;
            break;
        case "dynamic-forward":
            options.sshDynamicForward = value;
            break;
        case "proxy-command":
            options.sshProxyCommand = value;
            break;
        case "ssh-option":
            options.sshOptions ~= value;
            break;
        case "remote-path":
            options.sftpRemotePath = value;
            break;
        case "network":
            options.network = value;
            break;
        case "domain":
            options.domain = value;
            break;
        case "dns-server":
            options.dnsServer = value;
            break;
        case "record-type":
            options.recordType = value;
            break;
        case "wordlist":
            options.wordlist = value;
            break;
        case "ip":
            options.ipAddress = value;
            break;
        case "mac":
            options.macAddress = value;
            break;
        case "protocol":
            options.protocol = value;
            break;
        case "chain":
            options.chain = value;
            break;
        case "rule":
            options.rule = value;
            break;
        case "log":
            options.logPath = value;
            break;
        case "export":
            options.exportPath = value;
            break;
        case "process":
            options.processFilter = value;
            break;
        case "path":
            options.httpPath = value;
            break;
        case "port":
            options.port = to!ushort(value);
            break;
        case "start-port":
            options.startPort = to!ushort(value);
            break;
        case "end-port":
            options.endPort = to!ushort(value);
            break;
        case "count":
            options.count = to!uint(value);
            break;
        case "timeout":
            options.timeoutMs = to!uint(value);
            break;
        case "concurrency":
            options.concurrency = to!uint(value);
            break;
        case "duration":
            options.durationSec = to!uint(value);
            break;
        case "interval":
            options.intervalSec = to!uint(value);
            break;
        case "rate-limit":
            options.rateLimit = to!ulong(value);
            break;
        case "max-bps":
            options.maxBps = to!ulong(value);
            break;
        case "download-bps":
            options.downloadBps = to!ulong(value);
            break;
        case "upload-bps":
            options.uploadBps = to!ulong(value);
            break;
        case "pid":
            options.pid = to!int(value);
            break;
        case "threshold":
            options.threshold = to!double(value);
            break;
        default:
            return "unknown option --" ~ key;
        }
    }
    catch (Exception exception)
        return "invalid value for --" ~ key ~ ": " ~ exception.msg;
    return "";
}

public void printUsage()
{
    import std.stdio : writeln;

    writeln("ripnet - network diagnostics and authorized load testing");
    writeln("Usage: ripnet <command> [target] [options]");
    writeln("       ripnet --help");
    writeln("       ripnet --version | -v");
    writeln("\nCommands:");
    writeln("  Interfaces:  list-interfaces, show-stats, capture");
    writeln("  Reachability: ping, ping-tcp, ping-udp, ping-sweep, traceroute,");
    writeln("    traceroute-tcp, traceroute-udp, traceroute-icmp");
    writeln("  Scanning: scan, port-scan, network-scan, service-scan, os-fingerprint,");
    writeln("    udp-scan, syn-scan, fin-scan, xmas-scan, null-scan");
    writeln("  DNS: dns-lookup, dns-reverse, dns-query, dns-server-test, dns-trace,");
    writeln("    dns-bruteforce, dns-zone-transfer, dnssec-verify, dns-cache-flush");
    writeln("  Discovery: arp-table, arp-scan, arp-spoof-detect, arp-request, arp-reply,");
    writeln("    arp-cache-add, arp-cache-delete, discovery-ping, discovery-arp,");
    writeln("    discovery-dns, discovery-snmp, discovery-upnp, discovery-mdns,");
    writeln("    discovery-llmnr, discovery-netbios, discovery-smb, discovery-http,");
    writeln("    discovery-ssl");
    writeln("  System: netstat, netstat-listening, netstat-route, netstat-process,");
    writeln("    netstat-interface, netstat-group, netstat-timer, scan-processes,");
    writeln("    route-table, route-get, route-trace, route-monitor");
    writeln("  Firewall: firewall-status, firewall-log, firewall-add, firewall-delete,");
    writeln("    firewall-flush, block-ip, unblock-ip, block-port, unblock-port");
    writeln("  Monitoring: bandwidth-test, bandwidth-speedtest, bandwidth-monitor,");
    writeln("    bandwidth-history, bandwidth-limit, bandwidth-shaper, monitor-start,");
    writeln("    monitor-stop, monitor-status, monitor-alert, monitor-log, monitor-export");
    writeln("  Remote access: ssh, security-ssh, sftp");
    writeln("  Security: security-http, security-ssl, security-smtp,");
    writeln("    security-banner, security-dns, security-audit, security-scan");
    writeln("  Authorized stress testing: tcp-stress, http-stress, packet-flood,");
    writeln("    ping-flood, port-knocking, ddos");
    writeln("\nFlags:");
    writeln("  --help, -h                 show this command list");
    writeln("  --version, -v              print the current version");
    writeln("  --verbose, -V              show additional diagnostics");
    writeln("  --json, -j                 emit JSON where supported");
    writeln("  --promisc, -promisc       request promiscuous capture");
    writeln("  --interface NAME, -i NAME");
    writeln("  --host HOST, -H HOST      --hostname NAME, -N NAME");
    writeln("  --network CIDR, -n CIDR   --domain NAME, -d NAME");
    writeln("  --dns-server HOST, -s HOST   --record-type TYPE, -r TYPE");
    writeln("  --wordlist FILE, -w FILE  --ip ADDRESS, -I ADDRESS");
    writeln("  --mac ADDRESS, -m ADDRESS --protocol NAME, -P NAME");
    writeln("  --chain NAME, -C NAME     --rule RULE, -R RULE");
    writeln("  --log FILE, -l FILE       --export FILE, -e FILE");
    writeln("  --process NAME, -q NAME   --path PATH, -x PATH");
    writeln("  --port N, -p N            --start-port N, -sp N");
    writeln("  --end-port N, -ep N       --count N, -c N");
    writeln("  --timeout MS, -t MS       --concurrency N, -k N");
    writeln("  --duration SEC, -du SEC   --interval SEC, -int SEC");
    writeln("  --rate-limit N, -rl N     --max-bps N, -mb N");
    writeln("  --download-bps N, -db N   --upload-bps N, -ub N");
    writeln("  --pid N, -pid N           --threshold N, -th N");
    writeln("\nRun 'ripnet <command> --help' to see this command and flag reference.");
}

public void printDefaultUsage()
{
    import std.stdio : writeln;

    writeln("ripnet - network diagnostics and authorized load testing");
    writeln("Usage: ripnet <command> [arguments] [flags]");
    writeln("\nCore commands:");
    writeln("  list-interfaces         list network interfaces");
    writeln("  show-stats              show interface counters");
    writeln("  ping HOST               send a reachability probe");
    writeln("  scan HOST               scan a TCP port range");
    writeln("  service-scan HOST       identify an open service");
    writeln("  dns-lookup HOST         resolve a hostname");
    writeln("  capture                 capture packets with libpcap");
    writeln("  --help                  show help for the selected command");
    writeln("  --version               show the current installed ripnet version");
    writeln("\nOptions: --port N --start-port N --end-port N --timeout MS --count N");
    writeln("         --interface NAME --json --verbose");
}

public void printCommandUsage(Command command)
{
    import std.stdio : writeln;

    auto name = commandName(command);
    string usage = "ripnet " ~ name;
    string description = "run the " ~ name ~ " workflow";
    string[] flags;
    string example = "ripnet " ~ name;

    switch (command)
    {
    case Command.showVersion:
        usage = "ripnet --version | -v";
        description = "print the installed ripnet version";
        example = "ripnet --version";
        break;
    case Command.help:
        usage = "ripnet --help | -h";
        description = "show the command and flag reference";
        example = "ripnet --help";
        break;
    case Command.listInterfaces:
        usage ~= " [--json]";
        description = "list network interfaces";
        flags = ["--json, -j                 emit machine-readable output"];
        break;
    case Command.showStats:
        usage ~= " [--json]";
        description = "show interface counters";
        flags = ["--json, -j                 emit machine-readable output"];
        break;
    case Command.capture:
        usage ~= " --interface NAME [--filter EXPRESSION] [--promisc]";
        description = "capture packets with libpcap";
        flags = ["--interface NAME, -i NAME  select an interface",
            "--filter EXPRESSION, -f EXPRESSION",
            "--promisc, -promisc        request promiscuous capture"];
        break;
    case Command.ping:
    case Command.pingTcp:
        usage ~= " HOST [--port N]";
        description = "send a TCP reachability probe";
        flags = ["--port N, -p N            target port (default: 80)"];
        example ~= " example.com --port 443";
        break;
    case Command.pingUdp:
        usage ~= " HOST [--port N] [--timeout MS]";
        description = "send a UDP reachability probe";
        flags = ["--port N, -p N            target port (default: 53)",
            "--timeout MS, -t MS        timeout per probe"];
        example ~= " example.com --port 53";
        break;
    case Command.pingSweep:
    case Command.networkScan:
        usage ~= " NETWORK [--port N] [--timeout MS] [--json]";
        description = "scan hosts in a network range";
        flags = ["--network CIDR, -n CIDR   target network",
            "--port N, -p N            target port",
            "--timeout MS, -t MS        scan timeout",
            "--json, -j                 emit machine-readable output"];
        example ~= " 192.0.2.0/30 --timeout 500";
        break;
    case Command.scan:
    case Command.portScan:
    case Command.udpScan:
    case Command.synScan:
    case Command.finScan:
    case Command.xmasScan:
    case Command.nullScan:
        usage ~= " HOST [--start-port N] [--end-port N] [--timeout MS] [--verbose]";
        description = "scan a port range on a host";
        flags = ["--start-port N, -sp N      first port (default: 1)",
            "--end-port N, -ep N        last port (default: 1024)",
            "--timeout MS, -t MS        scan timeout",
            "--verbose, -V              show additional diagnostics",
            "--json, -j                 emit machine-readable output"];
        example ~= " 192.0.2.10 --start-port 1 --end-port 1024";
        break;
    case Command.serviceScan:
        usage ~= " HOST [--port N] [--timeout MS]";
        description = "identify an open service";
        flags = ["--port N, -p N            target port",
            "--timeout MS, -t MS        connection timeout"];
        example ~= " 192.0.2.10 --port 22";
        break;
    case Command.dnsLookup:
        usage ~= " HOST";
        description = "resolve a hostname";
        example ~= " example.com";
        break;
    case Command.dnsReverse:
        usage ~= " IP [--ip ADDRESS]";
        description = "perform a reverse DNS lookup";
        flags = ["--ip ADDRESS, -I ADDRESS  IP address to reverse"];
        example ~= " 192.0.2.10";
        break;
    case Command.dnsQuery:
        usage ~= " HOST [--record-type TYPE] [--dns-server HOST]";
        description = "query a DNS record";
        flags = ["--record-type TYPE, -r TYPE",
            "--dns-server HOST, -s HOST"];
        example ~= " example.com --record-type MX";
        break;
    case Command.dnsServerTest:
        usage ~= " HOST [--dns-server HOST]";
        description = "test a DNS server";
        flags = ["--dns-server HOST, -s HOST"];
        example ~= " 1.1.1.1";
        break;
    case Command.dnsBruteforce:
        usage ~= " --domain NAME --wordlist FILE";
        description = "discover names with a wordlist";
        flags = ["--domain NAME, -d NAME    target domain",
            "--wordlist FILE, -w FILE  wordlist to use"];
        example ~= " --domain example.com --wordlist names.txt";
        break;
    case Command.dnsCacheFlush:
        description = "flush the local DNS cache";
        break;
    case Command.traceroute:
    case Command.tracerouteTcp:
    case Command.tracerouteUdp:
    case Command.tracerouteIcmp:
        usage ~= " HOST [--port N]";
        description = "trace the route to a target";
        flags = ["--port N, -p N            target port"];
        example ~= " example.com";
        break;
    case Command.arpTable:
        description = "show the local ARP table";
        break;
    case Command.arpScan:
    case Command.discoveryArp:
        description = "scan local ARP neighbors";
        break;
    case Command.arpRequest:
        usage ~= " IP [--interface NAME]";
        description = "request an ARP neighbor entry";
        flags = ["--interface NAME, -i NAME  select an interface"];
        example ~= " 192.0.2.1 --interface en0";
        break;
    case Command.arpReply:
    case Command.arpCacheAdd:
        usage ~= " --ip ADDRESS --mac ADDRESS --interface NAME";
        description = "add an ARP cache or reply entry";
        flags = ["--ip ADDRESS, -I ADDRESS  IP address",
            "--mac ADDRESS, -m ADDRESS  MAC address",
            "--interface NAME, -i NAME  interface name"];
        break;
    case Command.arpCacheDelete:
        usage ~= " --ip ADDRESS --interface NAME";
        description = "delete an ARP cache entry";
        flags = ["--ip ADDRESS, -I ADDRESS  IP address",
            "--interface NAME, -i NAME  interface name"];
        break;
    case Command.arpSpoofDetect:
        usage ~= " [--interface NAME]";
        description = "check for suspicious ARP behavior";
        flags = ["--interface NAME, -i NAME  select an interface"];
        break;
    case Command.discoveryPing:
        usage ~= " --network CIDR";
        description = "discover hosts with ICMP probes";
        flags = ["--network CIDR, -n CIDR   target network"];
        example ~= " --network 192.0.2.0/30";
        break;
    case Command.discoveryDns:
        usage ~= " --domain NAME";
        description = "discover DNS information for a domain";
        flags = ["--domain NAME, -d NAME    target domain"];
        example ~= " --domain example.com";
        break;
    case Command.osFingerprint:
    case Command.vulnerabilityScan:
        usage ~= " HOST";
        description = "run the " ~ name ~ " check against a target";
        example ~= " example.com";
        break;
    case Command.dnsTrace:
    case Command.dnsZoneTransfer:
    case Command.dnssecVerify:
        usage ~= " HOST";
        description = "run the " ~ name ~ " check against a target";
        example ~= " example.com";
        break;
    case Command.discoverySnmp:
    case Command.discoveryUpnp:
    case Command.discoveryMdns:
    case Command.discoveryLlmnr:
    case Command.discoveryNetbios:
    case Command.discoverySmb:
    case Command.discoveryHttp:
    case Command.discoverySsl:
        description = "run an unavailable discovery adapter";
        break;
    case Command.securitySsh:
        usage ~= " HOST [--user NAME] [--port N] [--identity FILE] [--command CMD]";
        description = "open an interactive SSH connection";
        flags = ["--user NAME, -u NAME      remote SSH user",
            "--port N, -p N            SSH port (default: 22)",
            "--identity FILE           private key file",
            "--command CMD             run a remote command instead of a shell",
            "--jump-host HOST, -J HOST use a jump host",
            "--local-forward SPEC       local port forward (L)",
            "--remote-forward SPEC      remote port forward (R)",
            "--dynamic-forward SPEC     SOCKS proxy (D)",
            "--proxy-command CMD        custom proxy command",
            "--ssh-option OPTION        pass an OpenSSH -o option (repeatable)",
            "--agent-forwarding, -A     forward the SSH agent",
            "--x11-forwarding, -X       enable X11 forwarding",
            "--no-tty, -T              disable pseudo-terminal allocation"];
        example ~= " admin@example.com --identity ~/.ssh/id_ed25519";
        break;
    case Command.sftp:
        usage ~= " HOST [REMOTE_PATH] [--user NAME] [--port N] [--identity FILE]";
        description = "open an interactive SFTP session";
        flags = ["--user NAME, -u NAME      remote SFTP user",
            "--port N, -p N            SFTP/SSH port (default: 22)",
            "--identity FILE           private key file",
            "--remote-path PATH        open a remote path",
            "--jump-host HOST, -J HOST use a jump host",
            "--ssh-option OPTION        pass an OpenSSH -o option (repeatable)"];
        example ~= " deploy@example.com /var/www --identity ~/.ssh/id_ed25519";
        break;
    case Command.securityHttp:
    case Command.securitySsl:
    case Command.securitySmtp:
    case Command.securityBanner:
    case Command.securityDns:
    case Command.securityAudit:
    case Command.securityScan:
        usage ~= " HOST";
        description = "run the " ~ name ~ " check against a target";
        example ~= " example.com";
        break;
    case Command.netstat:
    case Command.netstatListening:
    case Command.netstatGroup:
    case Command.netstatTimer:
        usage ~= " [--json]";
        description = "show system network state";
        flags = ["--json, -j                 emit machine-readable output"];
        break;
    case Command.netstatRoute:
    case Command.routeTable:
        description = "show the system routing table";
        break;
    case Command.netstatProcess:
    case Command.scanProcesses:
        usage ~= " [--process NAME]";
        description = "show network-related processes";
        flags = ["--process NAME, -q NAME   filter by process"];
        break;
    case Command.netstatInterface:
        usage ~= " [--json]";
        description = "show network interface state";
        flags = ["--json, -j                 emit machine-readable output"];
        break;
    case Command.routeGet:
        usage ~= " HOST";
        description = "look up a route for a host";
        example ~= " 192.0.2.10";
        break;
    case Command.routeTrace:
    case Command.routeMonitor:
        usage ~= " HOST";
        description = "trace routes to a host";
        example ~= " 192.0.2.10";
        break;
    case Command.firewallStatus:
    case Command.firewallLog:
        description = "show firewall state or logging information";
        break;
    case Command.firewallAdd:
        usage ~= " --chain NAME --rule RULE";
        description = "add a firewall rule";
        flags = ["--chain NAME, -C NAME     firewall chain",
            "--rule RULE, -R RULE       rule definition"];
        break;
    case Command.firewallDelete:
        usage ~= " --chain NAME --port N";
        description = "delete a firewall rule by port";
        flags = ["--chain NAME, -C NAME     firewall chain",
            "--port N, -p N            target port"];
        break;
    case Command.firewallFlush:
        usage ~= " [--chain NAME]";
        description = "flush firewall rules";
        flags = ["--chain NAME, -C NAME     firewall chain"];
        break;
    case Command.blockIp:
    case Command.unblockIp:
        usage ~= " --ip ADDRESS";
        description = "add or remove an IP firewall block";
        flags = ["--ip ADDRESS, -I ADDRESS  IP address"];
        break;
    case Command.blockPort:
    case Command.unblockPort:
        usage ~= " --port N [--protocol NAME]";
        description = "add or remove a port firewall block";
        flags = ["--port N, -p N            target port",
            "--protocol NAME, -P NAME   transport protocol"];
        break;
    case Command.bandwidthTest:
    case Command.bandwidthMonitor:
        usage ~= " [--interface NAME] [--interval SEC]";
        description = "measure network bandwidth";
        flags = ["--interface NAME, -i NAME  select an interface",
            "--interval SEC, -int SEC   sampling interval"];
        break;
    case Command.bandwidthSpeedtest:
    case Command.bandwidthHistory:
    case Command.bandwidthLimit:
    case Command.bandwidthShaper:
        description = "run a bandwidth workflow";
        break;
    case Command.monitorStart:
        usage ~= " --interface NAME";
        description = "start or stop interface monitoring";
        flags = ["--interface NAME, -i NAME  select an interface"];
        break;
    case Command.monitorStop:
        description = "stop interface monitoring";
        break;
    case Command.monitorStatus:
        usage ~= " [--interface NAME]";
        description = "show monitor status";
        flags = ["--interface NAME, -i NAME  select an interface"];
        break;
    case Command.monitorAlert:
        usage ~= " --interface NAME --threshold N";
        description = "monitor an interface threshold";
        flags = ["--interface NAME, -i NAME  select an interface",
            "--threshold N, -th N       alert threshold"];
        break;
    case Command.monitorLog:
        usage ~= " --interface NAME --log FILE";
        description = "export monitor statistics to a log file";
        flags = ["--interface NAME, -i NAME  select an interface",
            "--log FILE, -l FILE        output log path"];
        break;
    case Command.monitorExport:
        usage ~= " --interface NAME --export FILE";
        description = "export monitor statistics";
        flags = ["--interface NAME, -i NAME  select an interface",
            "--export FILE, -e FILE     output path"];
        break;
    case Command.tcpStress:
    case Command.httpStress:
        usage ~= " HOST --port N [--duration SEC] [--concurrency N]";
        description = "run an authorized connection stress test";
        flags = ["--port N, -p N            target port",
            "--duration SEC, -du SEC    test duration",
            "--concurrency N, -k N      concurrent connections"];
        example ~= " example.com --port 443 --duration 10";
        break;
    case Command.packetFlood:
    case Command.pingFlood:
        usage ~= " HOST";
        description = "run a privileged traffic test";
        example ~= " 192.0.2.10";
        break;
    case Command.portKnocking:
        usage ~= " HOST";
        description = "perform a port knocking workflow";
        example ~= " 192.0.2.10";
        break;
    case Command.ddos:
        description = "show the controlled testing placeholder";
        break;
    default:
        description = "no command-specific options";
        break;
    }

    writeln("ripnet ", name, " - ", description);
    writeln("Usage: ", usage);
    writeln("\nFlags:");
    writeln("  --help, -h                 show this command help");
    foreach (flag; flags)
        writeln("  ", flag);
    writeln("\nExample:");
    writeln("  ", example);
}
