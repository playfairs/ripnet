module ripnet.network.traceroute;

import ripnet.model;
import ripnet.network.probe;
import std.stdio : writeln;

public PingResult[] trace(string host, ushort port = 33434, uint maxHops = 30)
{
    PingResult[] results;
    auto result = tcpProbe(host, port);
    results ~= result;
    return results;
}

public int printTrace(string host, ushort port = 33434)
{
    auto result = trace(host, port);
    foreach (hop; result)
        writeln("  ", hop.host, " ", hop.latencyMs, " ms", hop.success ? "" : " (unreachable)");
    return result[$ - 1].success ? 0 : -1;
}
