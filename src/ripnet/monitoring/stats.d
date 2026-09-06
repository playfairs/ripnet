module ripnet.monitoring.stats;

import ripnet.model;
import ripnet.platform.interfaces;

public NetworkInterface[] interfaces()
{
    return listInterfaces();
}

public NetworkInterface stats(string name)
{
    return interfaceStats(name);
}

public void printInterfaces(bool json = false)
{
    import std.stdio : writefln, writeln;

    auto values = listInterfaces();
    if (json)
    {
        writeln("[");
        foreach (index, item; values)
            writefln("  {\"name\":\"%s\",\"mac\":\"%s\",\"rx_bytes\":%d,\"tx_bytes\":%d}%s", item.name,
                    item.mac.value, item.rxBytes, item.txBytes, index + 1 == values.length ? ""
                    : ",");
        writeln("]");
        return;
    }
    foreach (item; values)
        writefln("%-16s %-18s mtu=%-6d rx=%d tx=%d", item.name, item.mac.value,
                item.mtu, item.rxBytes, item.txBytes);
}
