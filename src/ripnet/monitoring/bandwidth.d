module ripnet.monitoring.bandwidth;

import ripnet.model;
import ripnet.monitoring.stats;
import core.thread : Thread;
import core.time : dur;

public BandwidthStats measure(string interfaceName, uint intervalSec = 1)
{
    auto before = stats(interfaceName);
    Thread.sleep(dur!"seconds"(intervalSec));
    auto after = stats(interfaceName);
    BandwidthStats result;
    result.interfaceName = interfaceName;
    result.rxBytes = after.rxBytes;
    result.txBytes = after.txBytes;
    result.rxPackets = after.rxPackets;
    result.txPackets = after.txPackets;
    auto seconds = intervalSec ? intervalSec : 1;
    result.rxMbps = (after.rxBytes - before.rxBytes) * 8.0 / seconds / 1_000_000;
    result.txMbps = (after.txBytes - before.txBytes) * 8.0 / seconds / 1_000_000;
    return result;
}

public void print(BandwidthStats value)
{
    import std.stdio : writefln;

    writefln("%s: RX %.2f Mbps, TX %.2f Mbps", value.interfaceName, value.rxMbps, value.txMbps);
}
