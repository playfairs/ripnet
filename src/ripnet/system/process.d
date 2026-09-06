module ripnet.system.process;

import ripnet.platform.command;
import std.string : splitLines;
import std.algorithm : canFind;

public int list(string filter = "")
{
    auto result = run("lsof", ["-i"]);
    import std.stdio : writeln;

    foreach (line; result.output.splitLines)
        if (!filter.length || line.canFind(filter))
            writeln(line);
    return result.status;
}
