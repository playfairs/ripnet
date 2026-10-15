module ripnet.output;

import ripnet.model;
import ripnet.http.bulk : BulkResult;
import ripnet.http.client : HttpResponse;
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

public string httpResponse(HttpResponse value)
{
    JSONValue[] headers;
    foreach (header; value.headers)
        headers ~= JSONValue(header);

    string bodyText;
    bool textBody = true;
    textBody = validUtf8(value.body);
    if (textBody)
        bodyText = cast(string) value.body.idup;

    return render(makeObject([
        "status_code": JSONValue(value.statusCode),
        "transport_success": JSONValue(value.transportSuccess),
        "headers": JSONValue(headers),
        "body": JSONValue(textBody ? bodyText : ""),
        "body_encoding": JSONValue(textBody ? "utf-8" : "binary"),
        "body_bytes": JSONValue(value.body.length),
        "total_ms": JSONValue(value.totalMs),
        "connect_ms": JSONValue(value.connectMs),
        "first_byte_ms": JSONValue(value.firstByteMs),
        "error": JSONValue(value.error),
    ]));
}

public string httpBulk(BulkResult value)
{
    import std.algorithm : sort;
    import std.conv : to;
    import std.json : parseJSON;

    JSONValue[] responses;
    JSONValue[string] statusDistribution;
    ulong[string] statusCounts;
    double[] latencies;
    foreach (response; value.responses)
    {
        responses ~= parseJSON(httpResponse(response));
        if (response.transportSuccess)
        {
            auto status = to!string(response.statusCode);
            if (auto count = status in statusCounts)
                ++*count;
            else
                statusCounts[status] = 1;
            latencies ~= response.totalMs;
        }
    }
    foreach (status, count; statusCounts)
        statusDistribution[status] = JSONValue(count);
    latencies.sort;

    double minimumLatency = 0;
    double maximumLatency = 0;
    double meanLatency = 0;
    if (latencies.length)
    {
        minimumLatency = latencies[0];
        maximumLatency = latencies[$ - 1];
        foreach (latency; latencies)
            meanLatency += latency;
        meanLatency /= latencies.length;
    }
    auto requestsPerSecond = value.elapsedMs > 0
        ? value.responses.length * 1000.0 / value.elapsedMs : 0.0;

    return render(makeObject([
        "dry_run": JSONValue(value.dryRun),
        "request_count": JSONValue(value.plannedRequests),
        "completed": JSONValue(value.responses.length),
        "succeeded": JSONValue(value.succeeded),
        "failed": JSONValue(value.failed),
        "response_bytes": JSONValue(value.responseBytes),
        "elapsed_ms": JSONValue(value.elapsedMs),
        "requests_per_second": JSONValue(requestsPerSecond),
        "status_distribution": JSONValue(statusDistribution),
        "latency_min_ms": JSONValue(minimumLatency),
        "latency_max_ms": JSONValue(maximumLatency),
        "latency_mean_ms": JSONValue(meanLatency),
        "latency_p50_ms": JSONValue(percentile(latencies, 50)),
        "latency_p95_ms": JSONValue(percentile(latencies, 95)),
        "latency_p99_ms": JSONValue(percentile(latencies, 99)),
        "responses": JSONValue(responses),
    ]));
}

private double percentile(double[] sorted, uint percent)
{
    if (!sorted.length)
        return 0;
    auto rank = (percent * sorted.length + 99) / 100;
    return sorted[rank ? rank - 1 : 0];
}

private bool validUtf8(const(ubyte)[] bytes)
{
    size_t index;
    while (index < bytes.length)
    {
        auto first = bytes[index];
        if (first <= 0x7f)
        {
            ++index;
            continue;
        }

        size_t continuationCount;
        ubyte secondMinimum = 0x80;
        ubyte secondMaximum = 0xbf;
        if (first >= 0xc2 && first <= 0xdf)
            continuationCount = 1;
        else if (first >= 0xe0 && first <= 0xef)
        {
            continuationCount = 2;
            if (first == 0xe0)
                secondMinimum = 0xa0;
            else if (first == 0xed)
                secondMaximum = 0x9f;
        }
        else if (first >= 0xf0 && first <= 0xf4)
        {
            continuationCount = 3;
            if (first == 0xf0)
                secondMinimum = 0x90;
            else if (first == 0xf4)
                secondMaximum = 0x8f;
        }
        else
            return false;

        if (continuationCount > bytes.length - index - 1)
            return false;
        auto second = bytes[index + 1];
        if (second < secondMinimum || second > secondMaximum)
            return false;
        for (size_t offset = 2; offset <= continuationCount; ++offset)
            if (bytes[index + offset] < 0x80 || bytes[index + offset] > 0xbf)
                return false;
        index += continuationCount + 1;
    }
    return true;
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
