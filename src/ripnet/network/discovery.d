module ripnet.network.discovery;

import ripnet.model;
import ripnet.network.arp;
import ripnet.network.dns;
import ripnet.network.probe;
import ripnet.network.scan;
import ripnet.platform.command : run;

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
    {
        auto probe = run("ping", pingArguments(item.host));
        if (probe.success)
            result ~= DiscoveredHost(item.host, "", MacAddress(""), true, []);
    }
    return result;
}

private string[] pingArguments(string host)
{
    version (OSX)
        return ["-c", "1", "-W", "1000", host];
    version (linux)
        return ["-c", "1", "-W", "1", host];
    return ["-c", "1", host];
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

public int nmapDiscovery(string feature, string target, string interfaceName = "")
{
    import std.stdio : writeln;

    string script;
    switch (feature)
    {
    case "discovery-snmp": script = "snmp-info"; break;
    case "discovery-upnp": script = "broadcast-upnp-info"; break;
    case "discovery-mdns": script = "broadcast-dns-service-discovery"; break;
    case "discovery-llmnr": script = "broadcast-llmnr-discovery"; break;
    case "discovery-netbios": script = "nbstat"; break;
    case "discovery-smb": script = "smb-os-discovery"; break;
    case "discovery-http": script = "http-title"; break;
    case "discovery-ssl": script = "ssl-cert"; break;
    default:
        writeln(feature, ": no discovery adapter is registered");
        return -1;
    }

    string[] arguments = ["--script", script, "-Pn"];
    if (interfaceName.length)
    {
        arguments ~= "-e";
        arguments ~= interfaceName;
    }
    if (target.length)
        arguments ~= target;
    else
        arguments ~= " broadcast";

    auto result = run("nmap", arguments);
    if (!result.success)
    {
        writeln(feature, ": nmap is unavailable or the discovery failed");
        return -1;
    }
    writeln(result.output);
    return 0;
}
