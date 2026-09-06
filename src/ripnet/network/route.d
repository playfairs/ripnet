module ripnet.network.route;

import ripnet.model;
import ripnet.platform.command;
import std.file : exists, readText;
import std.string : split, splitLines;
import std.conv : to;

public Route[] table()
{
    Route[] routes;
    version (linux)
    {
        if (!exists("/proc/net/route"))
            return routes;
        foreach (line; readText("/proc/net/route").splitLines[1 .. $])
        {
            auto fields = line.split;
            if (fields.length < 8)
                continue;
            routes ~= Route(fields[0], hexAddress(fields[2]),
                    hexAddress(fields[7]), fields[0], to!uint(fields[6]));
        }
    }
    else
    {
        auto result = run("netstat", ["-rn"]);
        foreach (line; result.output.splitLines)
        {
            auto fields = line.split;
            if (fields.length >= 4 && fields[0] != "Destination")
                routes ~= Route(fields[0], fields[1], fields[2], fields[$ - 1], 0);
        }
    }
    return routes;
}

private string hexAddress(string value)
{
    auto number = to!uint("0x" ~ value);
    import std.format : format;

    return format("%d.%d.%d.%d", number & 255, (number >> 8) & 255,
            (number >> 16) & 255, (number >> 24) & 255);
}

public Route[] lookup(string destination)
{
    auto result = run("route", ["get", destination]);
    return result.success ? table : [];
}
