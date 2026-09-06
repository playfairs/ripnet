module ripnet.network.scan;

import ripnet.model;
import ripnet.network.probe;
import std.algorithm : map;
import std.array : array;
import std.conv : to;
import std.string : split;

public ScanResult[] scanPorts(string host, ushort firstPort, ushort lastPort, uint timeoutMs = 1000)
{
    ScanResult[] results;
    if (firstPort > lastPort)
        return results;
    foreach (port; firstPort .. cast(uint) lastPort + 1)
    {
        auto result = scanPort(host, cast(ushort) port, timeoutMs);
        if (result.open)
            results ~= result;
    }
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
    auto parts = network.split('/');
    if (parts.length != 2)
        return [];
    auto octets = parts[0].split('.');
    if (octets.length != 4)
        return [];
    uint address;
    foreach (octet; octets)
        address = (address << 8) | to!uint(octet);
    auto prefix = to!uint(parts[1]);
    if (prefix > 30)
        return [];
    uint hostCount = 1u << (32 - prefix);
    ScanResult[] results;
    foreach (offset; 1 .. hostCount - 1)
    {
        auto host = formatAddress(address + offset);
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
