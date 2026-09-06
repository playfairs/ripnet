module ripnet.network.discovery;

import ripnet.model;
import ripnet.network.arp;
import ripnet.network.dns;
import ripnet.network.probe;
import ripnet.network.scan;

public struct DiscoveredHost
{
    string address;
    string hostname;
    MacAddress mac;
    bool up;
    ScanResult[] services;
}

public DiscoveredHost[] ping(string network)
{
    DiscoveredHost[] result;
    foreach (item; networkScan(network))
        if (item.open)
            result ~= DiscoveredHost(item.host, "", MacAddress(""), true, []);
    return result;
}

public DiscoveredHost[] arp(string network)
{
    DiscoveredHost[] result;
    foreach (entry; table)
        result ~= DiscoveredHost(entry.ip.value, "", entry.mac, true, []);
    return result;
}

public DiscoveredHost[] dnsDiscovery(string domain)
{
    DiscoveredHost[] result;
    auto dnsResult = lookup(domain);
    foreach (address; dnsResult.addresses)
        result ~= DiscoveredHost(address, domain, MacAddress(""), true, []);
    return result;
}

public int unsupported(string feature)
{
    import std.stdio : writeln;

    writeln(feature, ": discovery is unavailable on this platform");
    return -1;
}
