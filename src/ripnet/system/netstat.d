module ripnet.system.netstat;

import ripnet.platform.command;
import std.string : splitLines;

public string[] connections(bool listening = false)
{
    auto result = run("ss", listening ? ["-lntup"] : ["-ntup"]);
    return result.output.splitLines;
}

public int print(bool listening = false, bool json = false)
{
    import std.stdio : writeln;

    foreach (line; connections(listening))
        writeln(line);
    return 0;
}

public int route()
{
    version (linux)
        return run("ip", ["route"]).status;
    return run("netstat", ["-rn"]).status;
}
