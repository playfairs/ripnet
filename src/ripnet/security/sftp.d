module ripnet.security.sftp;

import std.process : Pid, spawnProcess, wait;
import std.stdio : stderr, stdin, stdout;
import std.conv : to;

public int connect(
    string host,
    string user,
    ushort port,
    string identity,
    string remotePath,
    string jumpHost,
    string[] sshOptions,
)
{
    string[] command = ["sftp", "-P", to!string(port)];
    if (identity.length)
        command ~= ["-i", identity];
    if (jumpHost.length)
        command ~= ["-o", "ProxyJump=" ~ jumpHost];
    foreach (option; sshOptions)
        command ~= ["-o", option];
    command ~= user.length ? user ~ "@" ~ host : host;
    if (remotePath.length)
        command ~= [remotePath];

    try
    {
        Pid process = spawnProcess(command, stdin, stdout, stderr);
        return wait(process);
    }
    catch (Exception exception)
    {
        stderr.writeln("ripnet: unable to start sftp: ", exception.msg);
        return 127;
    }
}
