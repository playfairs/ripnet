module ripnet.app.main;

import ripnet.app.cli;
import ripnet.model;
import ripnet.monitoring.bandwidth;
import ripnet.monitoring.monitor;
import ripnet.monitoring.stats;
import arpModule = ripnet.network.arp;
import dnsModule = ripnet.network.dns;
import discoveryModule = ripnet.network.discovery;
import captureModule = ripnet.network.capture;
import probeModule = ripnet.network.probe;
import routeModule = ripnet.network.route;
import scanModule = ripnet.network.scan;
import tracerouteModule = ripnet.network.traceroute;
import targetModule = ripnet.network.target;
import securityModule = ripnet.security.security;
import stressModule = ripnet.stress.stress;
import firewallModule = ripnet.system.firewall;
import netstatModule = ripnet.system.netstat;
import processModule = ripnet.system.process;
import std.stdio : writeln, writefln;
import buildinfo : versionString;

int main(string[] args)
{
    auto parsed = parseArgs(args);
    if (!parsed.ok)
    {
        if (parsed.options.command != Command.help)
            printCommandError(parsed.options.command, parsed.error);
        else
            writeln("error: ", parsed.error);
        return 2;
    }
    auto options = parsed.options;
    if (options.command == Command.help || options.showHelp)
    {
        printUsage();
        return 0;
    }
    if (options.command == Command.showVersion)
    {
        writeln("ripnet ", versionString);
        return 0;
    }
    if (options.command == Command.capture && options.interfaceName.length == 0)
    {
        printCommandError(options.command, "missing interface");
        return 2;
    }
    if (requiresTarget(options))
    {
        printCommandError(options.command, "missing target");
        return 2;
    }
    if (hasInvalidScanTarget(options))
    {
        printCommandError(options.command, targetModule.invalidTargetMessage(options.host));
        return 2;
    }

    final switch (options.command)
    {
    case Command.listInterfaces:
    case Command.showStats:
        printInterfaces(options.json);
        return 0;
    case Command.ping:
    case Command.pingTcp:
        return printProbe(options.command,
                probeModule.tcpProbe(options.host, options.port ? options.port : 80));
    case Command.pingUdp:
        return printProbe(options.command,
                probeModule.udpProbe(options.host, options.port ? options.port : 53));
    case Command.pingSweep:
        return printScans(scanModule.networkScan(options.network.length
                ? options.network : options.host));
    case Command.scan:
    case Command.portScan:
    case Command.udpScan:
    case Command.synScan:
    case Command.finScan:
    case Command.xmasScan:
    case Command.nullScan:
        return printScans(scanModule.scanPorts(options.host, options.startPort,
                options.endPort, options.timeoutMs, options.verbose));
    case Command.networkScan:
        return printScans(scanModule.networkScan(options.network.length
                ? options.network : options.host, options.port, options.timeoutMs));
    case Command.osFingerprint:
        writeln("OS fingerprint: Unknown");
        return 0;
    case Command.vulnerabilityScan:
        printCommandError(options.command,
                "vulnerability scanning is unavailable for this target");
        return -1;
    case Command.serviceScan:
        return printScan(scanModule.serviceScan(options.host,
                options.port, options.timeoutMs));
    case Command.dnsLookup:
        return printDns(options.command, dnsModule.lookup(options.host));
    case Command.dnsReverse:
        writeln(dnsModule.reverseLookup(options.ipAddress.length
                ? options.ipAddress : options.host));
        return 0;
    case Command.dnsQuery:
        writeln(dnsModule.query(options.host, options.recordType));
        return 0;
    case Command.dnsServerTest:
        double average;
        auto success = dnsModule.serverTest(options.dnsServer.length
                ? options.dnsServer : options.host, average);
        if (!success)
            printCommandError(options.command, "DNS server unavailable");
        else
            writefln("DNS server: ok (%.2f ms)", average);
        return success ? 0 : -1;
    case Command.dnsBruteforce:
        return dnsModule.bruteForce(options.domain, options.wordlist);
    case Command.dnsCacheFlush:
        return dnsModule.cacheFlush();
    case Command.dnsTrace:
    case Command.dnssecVerify:
    case Command.dnsZoneTransfer:
        printCommandError(options.command,
                "operation is not supported by the selected platform adapter");
        return -1;
    case Command.arpTable:
        foreach (entry; arpModule.table())
            writefln("%-16s %-18s %s", entry.ip.value, entry.mac.value, entry.interfaceName);
        return 0;
    case Command.arpScan:
    case Command.discoveryArp:
        foreach (entry; arpModule.table())
            writeln(entry.ip.value, " ", entry.mac.value);
        return 0;
    case Command.arpRequest:
        return arpModule.request(options.interfaceName,
                options.ipAddress.length ? options.ipAddress : options.host);
    case Command.arpCacheAdd:
    case Command.arpReply:
        return arpModule.add(options.ipAddress, options.macAddress, options.interfaceName);
    case Command.arpCacheDelete:
        return arpModule.remove(options.ipAddress, options.interfaceName);
    case Command.arpSpoofDetect:
        printCommandError(options.command,
                "ARP spoof detection requires packet capture privileges");
        return 0;
    case Command.discoveryPing:
        foreach (host; discoveryModule.ping(options.network))
            writeln(host.address);
        return 0;
    case Command.discoveryDns:
        foreach (host; discoveryModule.dnsDiscovery(options.domain))
            writeln(host.address);
        return 0;
    case Command.discoverySnmp:
    case Command.discoveryUpnp:
    case Command.discoveryMdns:
    case Command.discoveryLlmnr:
    case Command.discoveryNetbios:
    case Command.discoverySmb:
    case Command.discoveryHttp:
    case Command.discoverySsl:
        return discoveryModule.unsupported(commandName(options.command));
    case Command.netstat:
        return netstatModule.print(false, options.json);
    case Command.netstatListening:
        return netstatModule.print(true, options.json);
    case Command.netstatRoute:
    case Command.routeTable:
        foreach (item; routeModule.table())
            writefln("%s via %s dev %s", item.destination, item.gateway, item.interfaceName);
        return 0;
    case Command.netstatProcess:
    case Command.scanProcesses:
        return processModule.list(options.processFilter);
    case Command.netstatInterface:
        printInterfaces(options.json);
        return 0;
    case Command.netstatGroup:
    case Command.netstatTimer:
        return netstatModule.print(false, options.json);
    case Command.routeGet:
        foreach (item; routeModule.lookup(options.host))
            writeln(item.destination);
        return 0;
    case Command.routeTrace:
    case Command.routeMonitor:
        return tracerouteModule.printTrace(options.host);
    case Command.firewallStatus:
        return firewallModule.status();
    case Command.firewallAdd:
        return firewallModule.add(options.chain, options.rule);
    case Command.firewallDelete:
        return firewallModule.remove(options.chain, options.port);
    case Command.firewallFlush:
        return firewallModule.flush(options.chain);
    case Command.blockIp:
        return firewallModule.blockIp(options.ipAddress);
    case Command.unblockIp:
        return firewallModule.unblockIp(options.ipAddress);
    case Command.blockPort:
        return firewallModule.blockPort(options.port, options.protocol);
    case Command.unblockPort:
        return firewallModule.unblockPort(options.port, options.protocol);
    case Command.firewallLog:
        printCommandError(options.command,
                "firewall logging is platform-managed");
        return 0;
    case Command.bandwidthTest:
    case Command.bandwidthMonitor:
        import ripnet.monitoring.bandwidth : measure, print;

        print(measure(options.interfaceName, options.intervalSec));
        return 0;
    case Command.bandwidthSpeedtest:
    case Command.bandwidthHistory:
    case Command.bandwidthLimit:
    case Command.bandwidthShaper:
        printCommandError(options.command, "operation is unavailable without a configured peer");
        return -1;
    case Command.monitorStart:
        return ripnet.monitoring.monitor.start(options.interfaceName);
    case Command.monitorStop:
        return ripnet.monitoring.monitor.stop();
    case Command.monitorStatus:
        auto state = ripnet.monitoring.monitor.status(options.interfaceName);
        import ripnet.monitoring.bandwidth : print;

        print(state.current);
        return 0;
    case Command.monitorAlert:
        return ripnet.monitoring.monitor.alert(options.interfaceName, options.threshold);
    case Command.monitorLog:
        return ripnet.monitoring.monitor.exportStats(options.interfaceName, options.logPath);
    case Command.monitorExport:
        return ripnet.monitoring.monitor.exportStats(options.interfaceName, options.exportPath);
    case Command.securitySsh:
        return printProbe(options.command,
                securityModule.ssh(options.host, options.port ? options.port : 22));
    case Command.securityHttp:
        return printProbe(options.command,
                securityModule.http(options.host, options.port ? options.port : 80));
    case Command.securitySsl:
        return printProbe(options.command,
                securityModule.ssl(options.host, options.port ? options.port : 443));
    case Command.securitySmtp:
        return printProbe(options.command,
                securityModule.smtp(options.host, options.port ? options.port : 25));
    case Command.securityBanner:
        return printProbe(options.command,
                securityModule.banner(options.host, options.port));
    case Command.securityAudit:
    case Command.securityScan:
    case Command.securityDns:
        return securityModule.audit(options.host);
    case Command.tcpStress:
    case Command.httpStress:
        auto stressResult = stressModule.tcp(options.host,
                options.port, options.durationSec, options.concurrency);
        writefln("connections: %d successful, %d failed",
                stressResult.successfulConnections, stressResult.failedConnections);
        return 0;
    case Command.packetFlood:
    case Command.pingFlood:
        printCommandError(options.command,
                "flood operations require an explicit privileged implementation");
        return -1;
    case Command.traceroute:
    case Command.tracerouteTcp:
    case Command.tracerouteUdp:
    case Command.tracerouteIcmp:
        return tracerouteModule.printTrace(options.host, options.port);
    case Command.capture:
        return captureModule.capture(options.interfaceName,
                options.filter, options.packetCount, options.promisc);
    case Command.portKnocking:
        printCommandError(options.command, "operation is not available");
        return -1;
    case Command.ddos:
        writeln("ddos: that's very minimalist of you.");
        return 0;
    case Command.help:
    case Command.showVersion:
        return 0;
    }
}

private void printCommandError(Command command, string message)
{
    writeln(commandName(command), ": ", message);
}

private bool hasInvalidScanTarget(CliOptions options)
{
    switch (options.command)
    {
    case Command.portScan:
    case Command.scan:
    case Command.serviceScan:
    case Command.udpScan:
    case Command.synScan:
    case Command.finScan:
    case Command.xmasScan:
    case Command.nullScan:
        return !targetModule.isAddressLike(options.host);
    default:
        return false;
    }
}

private bool requiresTarget(CliOptions options)
{
    switch (options.command)
    {
    case Command.ping:
    case Command.pingTcp:
    case Command.pingUdp:
    case Command.pingSweep:
    case Command.traceroute:
    case Command.tracerouteTcp:
    case Command.tracerouteUdp:
    case Command.tracerouteIcmp:
    case Command.portScan:
    case Command.scan:
    case Command.serviceScan:
    case Command.osFingerprint:
    case Command.vulnerabilityScan:
    case Command.networkScan:
    case Command.udpScan:
    case Command.synScan:
    case Command.finScan:
    case Command.xmasScan:
    case Command.nullScan:
    case Command.dnsLookup:
    case Command.dnsReverse:
    case Command.dnsQuery:
    case Command.dnsServerTest:
    case Command.dnsTrace:
    case Command.dnsBruteforce:
    case Command.dnsZoneTransfer:
    case Command.dnssecVerify:
    case Command.routeGet:
    case Command.routeTrace:
    case Command.routeMonitor:
    case Command.securitySsh:
    case Command.securityHttp:
    case Command.securitySsl:
    case Command.securitySmtp:
    case Command.securityBanner:
    case Command.securityDns:
    case Command.securityAudit:
    case Command.securityScan:
    case Command.tcpStress:
    case Command.httpStress:
        return options.host.length == 0
            && options.network.length == 0 && options.domain.length == 0
            && options.ipAddress.length == 0;
    default:
        return false;
    }
}

private int printProbe(Command command, PingResult result)
{
    if (result.success)
        writefln("%s: reachable (%.2f ms)", result.host, result.latencyMs);
    else
        printCommandError(command, result.error);
    return result.success ? 0 : -1;
}

private int printDns(Command command, DnsResult result)
{
    if (!result.success)
    {
        printCommandError(command, result.error);
        return -1;
    }
    foreach (address; result.addresses)
        writeln(address);
    return 0;
}

private int printScan(ScanResult result)
{
    writefln("%s:%d %s", result.host, result.port, result.open ? "open" : "closed");
    return result.open ? 0 : -1;
}

private int printScans(ScanResult[] results)
{
    foreach (result; results)
        if (result.open)
            printScan(result);
    return 0;
}
