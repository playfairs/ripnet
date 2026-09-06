module ripnet.network.arp;

import ripnet.model;
import ripnet.platform.command;
import std.file : exists, readText;
import std.string : split, splitLines, strip, indexOf;

public struct ArpEntry
{
    IpAddress ip;
    MacAddress mac;
    string interfaceName;
    bool permanent;
}

public ArpEntry[] table()
{
    ArpEntry[] entries;
    version (linux)
    {
        if (!exists("/proc/net/arp"))
            return entries;
        auto lines = readText("/proc/net/arp").splitLines;
        foreach (line; lines[1 .. $])
        {
            auto fields = line.split;
            if (fields.length < 6)
                continue;
            entries ~= ArpEntry(IpAddress(fields[0]), MacAddress(fields[3]),
                    fields[5], fields[2] == "0x6");
        }
    }
    else
    {
        auto result = run("arp", ["-an"]);
        foreach (line; result.output.splitLines)
        {
            auto open = line.indexOf('(');
            auto close = line.indexOf(')');
            if (open < 0 || close < open)
                continue;
            auto ip = line[open + 1 .. close];
            auto fields = line[close + 1 .. $].split;
            if (fields.length)
                entries ~= ArpEntry(IpAddress(ip), MacAddress(fields[1]), "", false);
        }
    }
    return entries;
}

public int request(string interfaceName, string ip)
{
    version (linux)
        return run("ip", ["neigh", "show", "dev", interfaceName, ip]).status;
    else
        return run("arp", ["-an", ip]).status;
}

public int add(string ip, string mac, string interfaceName)
{
    version (linux)
        return run("ip", [
        "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev",
        interfaceName
    ]).status;
    return -1;
}

public int remove(string ip, string interfaceName)
{
    version (linux)
        return run("ip", ["neigh", "del", ip, "dev", interfaceName]).status;
    return -1;
}
