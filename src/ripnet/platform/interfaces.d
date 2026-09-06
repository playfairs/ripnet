module ripnet.platform.interfaces;

import ripnet.model;
import std.file : exists, read, dirEntries, SpanMode, DirEntry;
import std.path : baseName, buildPath;
import std.string : splitLines, strip, split;
import std.conv : to;

private ulong readCounter(string interfaceName, string counter)
{
    version (linux)
    {
        auto path = buildPath("/sys/class/net", interfaceName, "statistics", counter);
        if (!path.exists)
            return 0;
        try
            return to!ulong(readText(path));
        catch (Exception)
            return 0;
    }
    return 0;
}

private string readText(string path)
{
    auto bytes = read(path);
    return (cast(string) bytes).strip;
}

public NetworkInterface[] listInterfaces()
{
    NetworkInterface[] result;
    version (linux)
    {
        foreach (entry; dirEntries("/sys/class/net", SpanMode.shallow))
        {
            auto name = baseName(entry.name);
            NetworkInterface item;
            item.name = name;
            item.address = "";
            auto addressPath = buildPath(entry.name, "address");
            if (addressPath.exists)
                item.mac = MacAddress(readText(addressPath));
            auto mtuPath = buildPath(entry.name, "mtu");
            if (mtuPath.exists)
            {
                try
                    item.mtu = to!uint(readText(mtuPath));
                catch (Exception)
                    item.mtu = 0;
            }
            item.rxPackets = readCounter(name, "rx_packets");
            item.txPackets = readCounter(name, "tx_packets");
            item.rxBytes = readCounter(name, "rx_bytes");
            item.txBytes = readCounter(name, "tx_bytes");
            item.rxErrors = readCounter(name, "rx_errors");
            item.txErrors = readCounter(name, "tx_errors");
            item.rxDropped = readCounter(name, "rx_dropped");
            item.txDropped = readCounter(name, "tx_dropped");
            result ~= item;
        }
    }
    else version (OSX)
    {
        import std.process : environment;
        import ripnet.platform.command : run;

        auto command = run("ifconfig", ["-l"]);
        foreach (name; command.output.splitLines)
            foreach (item; name.split)
                if (item.length)
                    result ~= NetworkInterface(name: item);
    }
    return result;
}

public NetworkInterface interfaceStats(string name)
{
    foreach (item; listInterfaces)
        if (item.name == name)
            return item;
    return NetworkInterface(name: name);
}
