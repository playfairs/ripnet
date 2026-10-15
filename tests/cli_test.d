import ripnet.app.cli;
import ripnet.model;
import std.algorithm : canFind;

private void assertOk(ParseResult result)
{
    assert(result.ok, result.error);
}

int main()
{
    auto scan = parseArgs([
        "ripnet", "scan", "example.com", "--start-port", "10", "--end-port=20",
        "--json", "-V"
    ]);
    assertOk(scan);
    assert(scan.options.command == Command.scan);
    assert(scan.options.host == "example.com");
    assert(scan.options.startPort == 10);
    assert(scan.options.endPort == 20);
    assert(scan.options.json);
    assert(scan.options.verbose);

    auto ssh = parseArgs([
        "ripnet", "ssh", "admin@example.com", "-p", "2222", "--ssh-option",
        "StrictHostKeyChecking=no", "--ssh-option=BatchMode=yes"
    ]);
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

    auto http = parseArgs([
        "ripnet", "http-request", "https://example.test/api", "--method", "PATCH",
        "--header", "X-Test: one", "--header=Accept: application/json", "--query",
        "q=two words", "--body-file", "payload.json", "--insecure", "--json"
    ]);
    assertOk(http);
    assert(http.options.command == Command.httpRequest);
    assert(http.options.host == "https://example.test/api");
    assert(http.options.httpMethod == "PATCH");
    assert(http.options.httpHeaders.length == 2);
    assert(http.options.httpQuery.length == 1);
    assert(http.options.httpBodyFile == "payload.json");
    assert(http.options.httpInsecureTls);
    assert(http.options.json);

    auto httpForm = parseArgs([
        "ripnet", "http-request", "https://example.test/api", "--method",
        "POST", "--form", "name=alice", "--form=city=Rome", "--json-body"
    ]);
    assertOk(httpForm);
    assert(httpForm.options.httpForm.length == 2);
    assert(httpForm.options.httpJsonBody);

    auto httpUnknown = parseArgs([
        "ripnet", "http-request", "https://example.test", "--wat"
    ]);
    assert(!httpUnknown.ok);
    assert(httpUnknown.error.canFind("unknown option"));
    return 0;
}
