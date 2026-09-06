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
        "interface", "filter", "host", "hostname", "network", "domain",
        "dns-server", "record-type", "wordlist", "ip", "mac", "protocol", "chain",
        "rule", "log", "export", "process", "path", "port", "start-port",
        "end-port", "count", "timeout", "concurrency", "duration", "interval",
        "rate-limit", "max-bps", "download-bps", "upload-bps", "pid", "threshold"
    ].canFind(key);
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
        if (endOfOptions || !token.startsWith("--"))
        {
            positional ~= token;
            continue;
        }
        auto option = token[2 .. $];
        string value;
        auto equals = option.indexOf('=');
        if (equals >= 0)
        {
            value = option[equals + 1 .. $];
            option = option[0 .. equals];
        }
        if (option == "help" || option == "h")
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
        if (option == "verbose" || option == "v")
        {
            options.verbose = true;
            continue;
        }
        if (option == "promisc")
        {
            options.promisc = true;
            continue;
        }
        if (!needsValue(option))
            return ParseResult(options, "unknown option --" ~ option, false);
        if (value.length == 0 && index + 1 < args.length)
            value = args[++index];
        if (value.length == 0)
            return ParseResult(options, "missing value for --" ~ option, false);
        auto error = assign(options, option, value);
        if (error.length)
            return ParseResult(options, error, false);
    }
    options.positional = positional;
    if (positional.length && positional[0] in known)
    {
        options.command = known[positional[0]];
        positional = positional[1 .. $];
    }
    if (!options.host.length && positional.length)
        options.host = positional[0];
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
    writeln("\nOptions: --port N --start-port N --end-port N --timeout MS --count N");
    writeln("         --interface NAME --json --verbose");
}
