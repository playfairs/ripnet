module ripnet.stress.stress;

import ripnet.model;
import ripnet.network.probe;
import core.thread : Thread;
import core.time : dur;
import std.datetime.stopwatch : StopWatch, AutoStart;

public StressResult tcp(string host, ushort port, uint durationSec, uint concurrency)
{
    StressResult result;
    auto watch = StopWatch(AutoStart.yes);
    auto deadline = durationSec ? durationSec : 1;
    while (watch.peek.total!"seconds" < deadline)
    {
        auto probe = tcpProbe(host, port);
        ++result.totalConnections;
        if (probe.success)
        {
            ++result.successfulConnections;
            result.minLatencyMs = result.successfulConnections == 1
                ? probe.latencyMs : min(result.minLatencyMs, probe.latencyMs);
            result.maxLatencyMs = max(result.maxLatencyMs, probe.latencyMs);
        }
        else
            ++result.failedConnections;
    }
    result.durationSec = watch.peek.total!"seconds";
    return result;
}

private double min(double a, double b)
{
    return a < b ? a : b;
}

private double max(double a, double b)
{
    return a > b ? a : b;
}
