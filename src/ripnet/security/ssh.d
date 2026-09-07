module ripnet.security.ssh;

import std.process : Pid, spawnProcess, wait;
import std.stdio : stderr, stdin, stdout;
import std.conv : to;

public int connect(
    string host,
    string user,
    ushort port,
    string identity,
    string remoteCommand,
    string jumpHost,
    string localForward,
    string remoteForward,
    string dynamicForward,
    string proxyCommand,
    string[] sshOptions,
    bool agentForwarding,
    bool x11Forwarding,
    bool noTty,
)
{
    string[] command = ["ssh", "-p", to!string(port)];
    appendOptions(command, identity, jumpHost, localForward, remoteForward,
        dynamicForward, proxyCommand, sshOptions, agentForwarding,
        x11Forwarding, noTty);
    command ~= user.length ? user ~ "@" ~ host : host;
    if (remoteCommand.length)
        command ~= [remoteCommand];
    return runInteractive(command);
}

private void appendOptions(
    ref string[] command,
    string identity,
    string jumpHost,
    string localForward,
    string remoteForward,
    string dynamicForward,
    string proxyCommand,
    string[] sshOptions,
    bool agentForwarding,
    bool x11Forwarding,
    bool noTty,
)
{
    if (identity.length)
        command ~= ["-i", identity];
    if (jumpHost.length)
        command ~= ["-J", jumpHost];
    if (localForward.length)
        command ~= ["-L", localForward];
    if (remoteForward.length)
        command ~= ["-R", remoteForward];
    if (dynamicForward.length)
        command ~= ["-D", dynamicForward];
    if (proxyCommand.length)
        command ~= ["-o", "ProxyCommand=" ~ proxyCommand];
    if (agentForwarding)
        command ~= ["-A"];
    if (x11Forwarding)
        command ~= ["-X"];
    if (noTty)
        command ~= ["-T"];
    foreach (option; sshOptions)
        command ~= ["-o", option];
}

private int runInteractive(string[] command)
{
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
