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
    import ripnet.output : interfacesJson;

    auto values = listInterfaces();
    if (json)
    {
        writeln(interfacesJson(values));
        return;
    }
    foreach (item; values)
        writefln("%-16s %-18s mtu=%-6d rx=%d tx=%d", item.name, item.mac.value,
                item.mtu, item.rxBytes, item.txBytes);
}
