module ripnet.system.firewall;

import ripnet.platform.command;
import ripnet.model;
import std.conv : to;
import std.string : split;

public int status()
{
    version (linux)
        return run("iptables", ["-L"]).status;
    version (OSX)
        return run("pfctl", ["-sr"]).status;
    return -1;
}

public int add(string chain, string rule)
{
    version (linux)
        return run("iptables", ["-A", chain] ~ rule.split).status;
    return -1;
}

public int remove(string chain, int ruleNumber)
{
    version (linux)
        return run("iptables", ["-D", chain, to!string(ruleNumber)]).status;
    return -1;
}

public int flush(string chain)
{
    version (linux)
        return run("iptables", ["-F", chain]).status;
    return -1;
}

public int blockIp(string ip)
{
    return add("INPUT", "-s " ~ ip ~ " -j DROP");
}

public int unblockIp(string ip)
{
    version (linux)
        return run("iptables", ["-D", "INPUT", "-s", ip, "-j", "DROP"]).status;
    return -1;
}

public int blockPort(ushort port, string protocol)
{
    return add("INPUT", "-p " ~ protocol ~ " --dport " ~ to!string(port) ~ " -j DROP");
}

public int unblockPort(ushort port, string protocol)
{
    version (linux)
        return run("iptables", [
            "-D", "INPUT", "-p", protocol, "--dport", to!string(port), "-j",
            "DROP"
    ]).status;
    return -1;
}
