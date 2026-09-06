module ripnet.network.dns;

import ripnet.model;
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
    auto result = lookup(hostname);
    return result.addresses.join("\n");
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
