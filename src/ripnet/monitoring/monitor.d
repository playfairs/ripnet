module ripnet.monitoring.monitor;

import ripnet.model;
import ripnet.monitoring.bandwidth;
import ripnet.monitoring.stats;

private bool running;
private MonitorSnapshot snapshot;

public int start(string interfaceName)
{
    running = true;
    snapshot.current = BandwidthStats(interfaceName: interfaceName);
    return 0;
}

public int stop()
{
    running = false;
    return 0;
}

public MonitorSnapshot status(string interfaceName)
{
    snapshot.previous = snapshot.current;
    snapshot.current = measure(interfaceName, 1);
    return snapshot;
}

public int alert(string interfaceName, double threshold)
{
    auto value = status(interfaceName);
    import std.stdio : writefln;

    if (value.current.rxMbps > threshold || value.current.txMbps > threshold)
        writefln("alert: %s exceeded %.2f Mbps", interfaceName, threshold);
    return 0;
}

public int exportStats(string interfaceName, string path)
{
    import std.file : write;
    import std.format : format;

    auto value = status(interfaceName);
    write(path, format("{\"interface\":\"%s\",\"rx_mbps\":%.2f,\"tx_mbps\":%.2f}\n",
            interfaceName, value.current.rxMbps, value.current.txMbps));
    return 0;
}
