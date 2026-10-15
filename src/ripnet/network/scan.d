module ripnet.network.scan;

import ripnet.model;
import ripnet.platform.command : run;
import ripnet.network.probe;
import ripnet.network.target : ipv4CidrError, parseIpv4Cidr;
import std.algorithm : map;
import std.array : array;
import std.conv : to;
import std.string : split;

public ScanResult[] scanPorts(string host, ushort firstPort, ushort lastPort,
        uint timeoutMs = 1000, bool verbose = false)
{
    import std.stdio : stderr, writefln;

    ScanResult[] results;
    if (firstPort > lastPort)
        return results;
    auto total = cast(uint) lastPort - firstPort + 1;
    stderr.writefln("scan: checking %s ports %d-%d", host, firstPort, lastPort);
    foreach (port; firstPort .. cast(uint) lastPort + 1)
    {
        auto completed = cast(uint) port - firstPort;
        if (verbose)
            stderr.writefln("scan: [%d/%d] checking port %d", completed + 1, total, port);
        auto result = scanPort(host, cast(ushort) port, timeoutMs);
        if (result.open)
        {
            results ~= result;
            stderr.writefln("scan: [%d/%d] port %d open", completed + 1, total, port);
        }
        else if (verbose)
            stderr.writefln("scan: [%d/%d] port %d closed or unreachable",
                    completed + 1, total, port);
    }
    stderr.writefln("scan: completed %d ports, %d open", total, results.length);
    return results;
}

public ScanResult serviceScan(string host, ushort port, uint timeoutMs = 1000)
{
    auto result = scanPort(host, port, timeoutMs);
    if (!result.open)
        return result;
    result.service = knownService(port);
    return result;
}

private string knownService(ushort port)
{
    switch (port)
    {
    case 21:
        return "ftp";
    case 22:
        return "ssh";
    case 25:
        return "smtp";
    case 53:
        return "dns";
    case 80:
        return "http";
    case 110:
        return "pop3";
    case 143:
        return "imap";
    case 443:
        return "https";
    case 3306:
        return "mysql";
    case 5432:
        return "postgresql";
    default:
        return "unknown";
    }
}

public ScanResult[] networkScan(string network, ushort port = 0, uint timeoutMs = 1000)
{
    if (ipv4CidrError(network).length)
        return [];
    uint address;
    uint prefix;
    if (!parseIpv4Cidr(network, address, prefix))
        return [];

    auto mask = prefix == 0 ? 0u : uint.max << (32 - prefix);
    address &= mask;
    auto addressCount = 1UL << (32 - prefix);
    auto firstOffset = prefix >= 31 ? 0UL : 1UL;
    auto endOffset = prefix >= 31 ? addressCount : addressCount - 1;
    ScanResult[] results;
    foreach (offset; firstOffset .. endOffset)
    {
        auto host = formatAddress(cast(uint)(address + offset));
        if (port)
            results ~= scanPort(host, port, timeoutMs);
        else
            results ~= ScanResult(host, 0, false, "", "", 0);
    }
    return results;
}

private string formatAddress(uint address)
{
    import std.format : format;

    return format("%d.%d.%d.%d", (address >> 24) & 255, (address >> 16) & 255,
            (address >> 8) & 255, address & 255);
}

public ScanResult[] scanVariant(string host, ushort firstPort, ushort lastPort, uint timeoutMs = 1000)
{
    return scanPorts(host, firstPort, lastPort, timeoutMs);
}

public int osFingerprint(string host)
{
    return printNmap(["-O", "--osscan-guess", host],
            "os-fingerprint: nmap is unavailable or the scan failed");
}

public int vulnerabilityScan(string host)
{
    return printNmap(["--script", "vuln", host],
            "vuln-scan: nmap is unavailable or the scan failed");
}

private int printNmap(string[] arguments, string failure)
{
    import std.stdio : writeln;

    auto result = run("nmap", arguments);
    if (!result.success)
    {
        writeln(failure);
        return -1;
    }
    writeln(result.output);
    return 0;
}
