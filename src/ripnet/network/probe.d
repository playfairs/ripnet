module ripnet.network.probe;

import ripnet.model;
import ripnet.network.target : invalidTargetMessage, isAddressLike;
import std.socket;
import std.datetime.stopwatch : StopWatch, AutoStart;
import std.datetime : dur;

private Address[] resolve(string host, ushort port)
{
    try
        return getAddress(host, port);
    catch (Exception)
        return [];
}

public PingResult tcpProbe(string host, ushort port, uint timeoutMs = 1000)
{
    PingResult result;
    result.host = host;
    if (!isAddressLike(host))
    {
        result.error = invalidTargetMessage(host);
        return result;
    }
    auto addresses = resolve(host, port);
    if (!addresses.length)
    {
        result.error = "address resolution failed";
        return result;
    }
    auto watch = StopWatch(AutoStart.yes);
    try
    {
        auto socket = new Socket(addresses[0].addressFamily, SocketType.STREAM);
        scope (exit)
            socket.close();
        socket.connect(addresses[0]);
        result.success = true;
        result.address = addresses[0].toString;
        result.latencyMs = watch.peek.total!"msecs";
    }
    catch (Exception exception)
        result.error = exception.msg;
    return result;
}

public PingResult udpProbe(string host, ushort port)
{
    PingResult result;
    result.host = host;
    if (!isAddressLike(host))
    {
        result.error = invalidTargetMessage(host);
        return result;
    }
    auto addresses = resolve(host, port);
    if (!addresses.length)
    {
        result.error = "address resolution failed";
        return result;
    }
    try
    {
        auto socket = new Socket(addresses[0].addressFamily, SocketType.DGRAM);
        scope (exit)
            socket.close();
        ubyte[] payload = cast(ubyte[]) "ripnet".dup;
        socket.sendTo(payload, addresses[0]);
        result.success = true;
        result.address = addresses[0].toString;
    }
    catch (Exception exception)
        result.error = exception.msg;
    return result;
}

public ScanResult scanPort(string host, ushort port, uint timeoutMs = 1000)
{
    auto probe = tcpProbe(host, port, timeoutMs);
    return ScanResult(host, port, probe.success, "", "", probe.latencyMs);
}
