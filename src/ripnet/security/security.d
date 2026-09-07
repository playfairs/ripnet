module ripnet.security.security;

import ripnet.model;
import ripnet.network.probe : tcpProbe;
import std.process : Pid, spawnProcess, wait;
import std.stdio : stderr, stdin, stdout;
import std.conv : to;

public PingResult ssh(string host, ushort port = 22)
{
    return tcpProbe(host, port);
}

public int connectSsh(
    string host,
    string user,
    ushort port,
    string identity,
    string remoteCommand,
)
{
    string[] command = ["ssh"];
    command ~= ["-p", to!string(port)];
    if (identity.length)
        command ~= ["-i", identity];
    command ~= user.length ? user ~ "@" ~ host : host;
    if (remoteCommand.length)
        command ~= [remoteCommand];

    try
    {
        Pid process = spawnProcess(command, stdin, stdout, stderr);
        return wait(process);
    }
    catch (Exception exception)
    {
        stderr.writeln("ripnet: unable to start ssh: ", exception.msg);
        return 127;
    }
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
