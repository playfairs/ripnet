module ripnet.network.dns;

import ripnet.model;
import ripnet.network.target : invalidTargetMessage, isAddressLike;
import ripnet.platform.command : CommandResult, run;
import std.datetime.stopwatch : StopWatch, AutoStart;
import std.socket : Address, getAddress;
import std.string : splitLines, strip, split;
import std.array : join;
import std.stdio : writeln;

public DnsResult lookup(string hostname)
{
    auto watch = StopWatch(AutoStart.yes);
    DnsResult result;
    result.hostname = hostname;
    if (!isAddressLike(hostname))
    {
        result.error = invalidTargetMessage(hostname);
        return result;
    }
    try
    {
        Address[] addresses = getAddress(hostname, 0);
        foreach (address; addresses)
            result.addresses ~= address.toString.split(':')[0];
        result.success = result.addresses.length > 0;
    }
    catch (Exception exception)
    {
        result.error = exception.msg;
        result.success = false;
    }
    result.responseTimeMs = watch.peek.total!"msecs";
    return result;
}

public string reverseLookup(string address)
{
    try
    {
        auto addresses = getAddress(address, 0);
        return addresses.length ? addresses[0].toString : "";
    }
    catch (Exception)
        return "";
}

public string query(string hostname, string recordType)
{
    auto result = runDig(["+short", recordType, hostname]);
    if (result.success)
        return result.output;
    if (recordType == "A")
        return lookup(hostname).addresses.join("\n");
    return "";
}

public int trace(string hostname)
{
    return printDig(["+trace", hostname]);
}

public int zoneTransfer(string hostname)
{
    auto nameservers = runDig(["+short", "NS", hostname]);
    if (!nameservers.success || !nameservers.output.length)
    {
        writeln("dns-zone-transfer: no authoritative nameserver found");
        return -1;
    }

    foreach (name; nameservers.output.splitLines)
    {
        auto server = name.strip;
        if (!server.length)
            continue;
        auto result = runDig(["AXFR", hostname, "@" ~ server]);
        if (result.success && result.output.length)
        {
            writeln(result.output);
            return 0;
        }
    }
    writeln("dns-zone-transfer: transfer refused or unavailable");
    return -1;
}

public int verifyDnssec(string hostname)
{
    auto result = runDig(["+dnssec", "+multi", "DNSKEY", hostname]);
    if (!result.success)
    {
        writeln("dnssec-verify: dig is unavailable or the query failed");
        return -1;
    }
    writeln(result.output.length ? result.output : "dnssec-verify: no DNSKEY records found");
    return result.output.length ? 0 : -1;
}

private CommandResult runDig(string[] arguments)
{
    return run("dig", arguments);
}

private int printDig(string[] arguments)
{
    auto result = runDig(arguments);
    if (!result.success)
    {
        writeln("dns: dig is unavailable or the query failed");
        return -1;
    }
    writeln(result.output);
    return 0;
}

public bool serverTest(string server, out double averageMs)
{
    auto result = lookup(server);
    averageMs = result.responseTimeMs;
    return result.success;
}

public int bruteForce(string domain, string wordlist)
{
    import std.file : readText;

    foreach (word; readText(wordlist).splitLines)
    {
        auto candidate = word.strip ~ "." ~ domain;
        auto result = lookup(candidate);
        if (result.success)
            writeln(candidate, ": ", result.addresses.join(", "));
    }
    return 0;
}

public int cacheFlush()
{
    version (linux)
        return 0;
    return 0;
}
