import ripnet.app.cli;
import ripnet.model;
import std.algorithm : canFind;

private void assertOk(ParseResult result)
{
    assert(result.ok, result.error);
}

int main()
{
    auto scan = parseArgs(["ripnet", "scan", "example.com", "--start-port", "10",
        "--end-port=20", "--json", "-V"]);
    assertOk(scan);
    assert(scan.options.command == Command.scan);
    assert(scan.options.host == "example.com");
    assert(scan.options.startPort == 10);
    assert(scan.options.endPort == 20);
    assert(scan.options.json);
    assert(scan.options.verbose);

    auto ssh = parseArgs(["ripnet", "ssh", "admin@example.com", "-p", "2222",
        "--ssh-option", "StrictHostKeyChecking=no", "--ssh-option=BatchMode=yes"]);
    assertOk(ssh);
    assert(ssh.options.command == Command.securitySsh);
    assert(ssh.options.port == 2222);
    assert(ssh.options.sshOptions.length == 2);
    assert(ssh.options.sshOptions.canFind("BatchMode=yes"));

    auto help = parseArgs(["ripnet", "dns-query", "example.com", "--help"]);
    assertOk(help);
    assert(help.options.command == Command.dnsQuery);
    assert(help.options.showHelp);

    auto missing = parseArgs(["ripnet", "scan", "--timeout"]);
    assert(!missing.ok);
    assert(missing.error.canFind("missing value"));

    auto invalid = parseArgs(["ripnet", "scan", "host", "--start-port", "nope"]);
    assert(!invalid.ok);
    assert(invalid.error.canFind("invalid value"));

    auto unknown = parseArgs(["ripnet", "scan", "host", "--wat"]);
    assert(!unknown.ok);
    assert(unknown.error.canFind("unknown option"));
    return 0;
}
