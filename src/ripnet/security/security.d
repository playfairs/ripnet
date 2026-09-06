module ripnet.security.security;

import ripnet.model;
import ripnet.network.probe;

public PingResult ssh(string host, ushort port = 22)
{
    return tcpProbe(host, port);
}

public PingResult http(string host, ushort port = 80)
{
    return tcpProbe(host, port);
}

public PingResult smtp(string host, ushort port = 25)
{
    return tcpProbe(host, port);
}

public PingResult ssl(string host, ushort port = 443)
{
    return tcpProbe(host, port);
}

public PingResult banner(string host, ushort port)
{
    return tcpProbe(host, port);
}

public int audit(string host)
{
    auto result = tcpProbe(host, 22);
    import std.stdio : writeln;

    writeln(result.success ? "SSH reachable" : "SSH unavailable");
    return result.success ? 0 : -1;
}
