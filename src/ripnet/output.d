module ripnet.output;

import ripnet.model;
import ripnet.network.arp : ArpEntry;
import std.json : JSONValue;

private string render(JSONValue value)
{
    return value.toString();
}

private JSONValue makeObject(JSONValue[string] fields)
{
    return JSONValue(fields);
}

public string ping(PingResult value)
{
    return render(makeObject([
        "host": JSONValue(value.host),
        "address": JSONValue(value.address),
        "success": JSONValue(value.success),
        "latency_ms": JSONValue(value.latencyMs),
        "error": JSONValue(value.error),
    ]));
}

public string dns(DnsResult value)
{
    JSONValue[] addresses;
    foreach (address; value.addresses)
        addresses ~= JSONValue(address);
    return render(makeObject([
        "hostname": JSONValue(value.hostname),
        "addresses": JSONValue(addresses),
        "response_time_ms": JSONValue(value.responseTimeMs),
        "success": JSONValue(value.success),
        "error": JSONValue(value.error),
    ]));
}

public string dnsQuery(string hostname, string recordType, string value)
{
    return render(makeObject([
        "hostname": JSONValue(hostname),
        "record_type": JSONValue(recordType),
        "answer": JSONValue(value),
    ]));
}

public string lines(string[] values)
{
    JSONValue[] result;
    foreach (value; values)
        result ~= JSONValue(value);
    return render(JSONValue(result));
}

public string arpEntriesJson(ArpEntry[] values)
{
    JSONValue[] result;
    foreach (value; values)
    {
        result ~= makeObject([
            "ip": JSONValue(value.ip.value),
            "mac": JSONValue(value.mac.value),
            "interface": JSONValue(value.interfaceName),
            "permanent": JSONValue(value.permanent),
        ]);
    }
    return render(JSONValue(result));
}

public string scan(ScanResult value)
{
    return render(scanValue(value));
}

private JSONValue scanValue(ScanResult value)
{
    return makeObject([
        "host": JSONValue(value.host),
        "port": JSONValue(value.port),
        "open": JSONValue(value.open),
        "service": JSONValue(value.service),
        "banner": JSONValue(value.banner),
        "latency_ms": JSONValue(value.latencyMs),
    ]);
}

public string scans(ScanResult[] values)
{
    JSONValue[] result;
    foreach (value; values)
        result ~= scanValue(value);
    return render(JSONValue(result));
}

public string interfacesJson(NetworkInterface[] values)
{
    JSONValue[] result;
    foreach (value; values)
    {
        result ~= makeObject([
            "name": JSONValue(value.name),
            "address": JSONValue(value.address),
            "mac": JSONValue(value.mac.value),
            "mtu": JSONValue(value.mtu),
            "rx_packets": JSONValue(value.rxPackets),
            "tx_packets": JSONValue(value.txPackets),
            "rx_bytes": JSONValue(value.rxBytes),
            "tx_bytes": JSONValue(value.txBytes),
            "rx_errors": JSONValue(value.rxErrors),
            "tx_errors": JSONValue(value.txErrors),
            "rx_dropped": JSONValue(value.rxDropped),
            "tx_dropped": JSONValue(value.txDropped),
        ]);
    }
    return render(JSONValue(result));
}

public string routesJson(Route[] values)
{
    JSONValue[] result;
    foreach (value; values)
    {
        result ~= makeObject([
            "destination": JSONValue(value.destination),
            "gateway": JSONValue(value.gateway),
            "mask": JSONValue(value.mask),
            "interface": JSONValue(value.interfaceName),
            "metric": JSONValue(value.metric),
        ]);
    }
    return render(JSONValue(result));
}

public string firewallRules(FirewallRule[] values)
{
    JSONValue[] result;
    foreach (value; values)
    {
        result ~= makeObject([
            "chain": JSONValue(value.chain),
            "target": JSONValue(value.target),
            "protocol": JSONValue(value.protocol),
            "source": JSONValue(value.source),
            "destination": JSONValue(value.destination),
            "options": JSONValue(value.options),
        ]);
    }
    return render(JSONValue(result));
}
