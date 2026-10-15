module ripnet.network.dns;

import ripnet.model;
import ripnet.network.target : invalidTargetMessage, isAddressLike;
import ripnet.platform.command : CommandResult, run;
import core.time : MonoTime, dur;
import std.datetime.stopwatch : StopWatch, AutoStart;
import std.socket : Address, getAddress;
import std.string : splitLines, strip, split, toLower;
import std.array : join;
import std.stdio : writeln;

private enum size_t maxCachedLookups = 4096;
private __gshared Object dnsCacheLock;
private __gshared DnsCacheEntry[string] dnsCache;

private struct DnsCacheEntry
{
    DnsResult result;
    MonoTime expiresAt;
}

shared static this()
{
    dnsCacheLock = new Object;
}

private string normalizedCacheKey(string hostname)
{
    auto key = hostname.toLower;
    if (key.length > 1 && key[$ - 1] == '.')
        key = key[0 .. $ - 1];
    return key;
}

private bool getCachedResult(string key, MonoTime now, out DnsResult result)
{
    synchronized (dnsCacheLock)
    {
        if (auto entry = key in dnsCache)
        {
            if (now < entry.expiresAt)
            {
                result = entry.result;
                return true;
            }
            dnsCache.remove(key);
        }
    }
    return false;
}

private void storeCachedResult(string key, DnsResult result, MonoTime now)
{
    auto expiresAt = now + dur!"seconds"(60);
    synchronized (dnsCacheLock)
    {
        string[] expiredKeys;
        foreach (cachedKey, entry; dnsCache)
            if (!(now < entry.expiresAt))
                expiredKeys ~= cachedKey;
        foreach (expiredKey; expiredKeys)
            dnsCache.remove(expiredKey);

        if (key !in dnsCache && dnsCache.length >= maxCachedLookups)
        {
            string oldestKey;
            MonoTime oldestExpiry;
            bool foundOldest;
            foreach (cachedKey, entry; dnsCache)
            {
                if (!foundOldest || entry.expiresAt < oldestExpiry)
                {
                    oldestKey = cachedKey;
                    oldestExpiry = entry.expiresAt;
                    foundOldest = true;
                }
            }
            if (foundOldest)
                dnsCache.remove(oldestKey);
        }

        dnsCache[key] = DnsCacheEntry(result, expiresAt);
    }
}

private size_t clearCachedResults()
{
    synchronized (dnsCacheLock)
    {
        auto count = dnsCache.length;
        dnsCache = null;
        return count;
    }
}

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
    auto key = normalizedCacheKey(hostname);
    DnsResult cachedResult;
    if (getCachedResult(key, MonoTime.currTime, cachedResult))
    {
        cachedResult.hostname = hostname;
        cachedResult.responseTimeMs = watch.peek.total!"msecs";
        return cachedResult;
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
    if (result.success)
        storeCachedResult(key, result, MonoTime.currTime);
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
    import std.stdio : stderr, writefln, writeln;

    auto clearedEntries = clearCachedResults();
    version (OSX)
    {
        import core.sys.posix.unistd : geteuid;

        if (geteuid() != 0)
        {
            stderr.writefln("dns-cache-flush: cleared %s ripnet entries; macOS flush requires root, run `sudo ripnet dns-cache-flush`",
                    clearedEntries);
            return 1;
        }

        auto flush = run("dscacheutil", ["-flushcache"]);
        if (!flush.success)
        {
            stderr.writefln("dns-cache-flush: dscacheutil -flushcache failed (status %d)%s",
                    flush.status, flush.error.length ? ": " ~ flush.error : "");
            return 1;
        }

        auto restart = run("killall", ["-HUP", "mDNSResponder"]);
        if (!restart.success)
        {
            stderr.writefln(
                    "dns-cache-flush: dscacheutil succeeded, but killall -HUP mDNSResponder failed (status %d)%s",
                    restart.status, restart.error.length ? ": " ~ restart.error : "");
            return 1;
        }

        writeln("DNS cache flushed and mDNSResponder signaled; cleared ",
                clearedEntries, " ripnet entries.");
        return 0;
    }
    else
    {
        writefln("dns-cache-flush: cleared %s ripnet entries.", clearedEntries);
        return 0;
    }
}

unittest
{
    clearCachedResults();
    auto now = MonoTime.currTime;
    DnsResult result;
    result.hostname = "Example.test";
    result.addresses = ["192.0.2.20"];
    result.success = true;
    storeCachedResult(normalizedCacheKey("Example.test."), result, now);

    DnsResult cached;
    assert(getCachedResult(normalizedCacheKey("example.TEST"), now, cached));
    assert(cached.addresses.length == 1);
    assert(cached.addresses[0] == "192.0.2.20");
    assert(!getCachedResult(normalizedCacheKey("example.test"), now + dur!"seconds"(61), cached));

    storeCachedResult("another.test", result, now);
    assert(clearCachedResults() == 1);
    assert(!getCachedResult("another.test", now, cached));
}
