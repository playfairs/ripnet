module ripnet.platform.command;

import std.process : Config, execute;
import std.string : strip, replace;

public struct CommandResult
{
    int status;
    string output;
    string error;

    @property bool success() const
    {
        return status == 0;
    }
}

public CommandResult run(string program, string[] args = [])
{
    string[] command = [program];
    command ~= args;
    try
    {
        auto result = execute(command, null, Config.none);
        return CommandResult(result.status, result.output.strip, "");
    }
    catch (Exception exception)
    {
        return CommandResult(-1, "", exception.msg);
    }
}

public string shellQuote(string value)
{
    return "'" ~ value.replace("'", "'\\''") ~ "'";
}
