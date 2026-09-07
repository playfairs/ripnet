module ripnet.model;

import std.datetime : Duration, dur;
import std.conv : to;

public enum Command
{
    help,
    showVersion,
    listInterfaces,
    showStats,
    capture,
    ping,
    pingTcp,
    pingUdp,
    pingSweep,
    traceroute,
    tracerouteTcp,
    tracerouteUdp,
    tracerouteIcmp,
    portScan,
    scan,
    serviceScan,
    osFingerprint,
    vulnerabilityScan,
    networkScan,
    udpScan,
    synScan,
    finScan,
    xmasScan,
    nullScan,
    dnsLookup,
    dnsReverse,
    dnsQuery,
    dnsServerTest,
    dnsTrace,
    dnsBruteforce,
    dnsZoneTransfer,
    dnssecVerify,
    dnsCacheFlush,
    arpTable,
    arpScan,
    arpSpoofDetect,
    arpRequest,
    arpReply,
    arpCacheAdd,
    arpCacheDelete,
    discoveryPing,
    discoveryArp,
    discoveryDns,
    discoverySnmp,
    discoveryUpnp,
    discoveryMdns,
    discoveryLlmnr,
    discoveryNetbios,
    discoverySmb,
    discoveryHttp,
    discoverySsl,
    netstat,
    netstatListening,
    netstatRoute,
    netstatProcess,
    netstatInterface,
    netstatGroup,
    netstatTimer,
    scanProcesses,
    routeTable,
    routeGet,
    routeTrace,
    routeMonitor,
    firewallStatus,
    firewallLog,
    firewallAdd,
    firewallDelete,
    firewallFlush,
    blockIp,
    unblockIp,
    blockPort,
    unblockPort,
    bandwidthTest,
    bandwidthSpeedtest,
    bandwidthMonitor,
    bandwidthHistory,
    bandwidthLimit,
    bandwidthShaper,
    monitorStart,
    monitorStop,
    monitorStatus,
    monitorAlert,
    monitorLog,
    monitorExport,
    securitySsh,
    securityHttp,
    securitySsl,
    securitySmtp,
    securityBanner,
    securityDns,
    securityAudit,
    securityScan,
    tcpStress,
    httpStress,
    packetFlood,
    pingFlood,
    portKnocking,
    ddos,
}

public string commandName(Command command)
{
    auto name = to!string(command);
    string result;
    foreach (character; name)
    {
        if (character >= 'A' && character <= 'Z')
        {
            result ~= '-';
            result ~= cast(char)(character - 'A' + 'a');
        }
        else
            result ~= character;
    }
    return result;
}

public struct CliOptions
{
    Command command = Command.help;
    bool showHelp;
    string interfaceName;
    string filter;
    string host;
    string hostname;
    string sshUser;
    string sshIdentity;
    string sshCommand;
    string network;
    string domain;
    string dnsServer;
    string recordType = "A";
    string wordlist;
    string ipAddress;
    string macAddress;
    string protocol = "tcp";
    string chain = "INPUT";
    string rule;
    string logPath;
    string exportPath;
    string processFilter;
    string httpPath = "/";
    ushort port;
    ushort startPort = 1;
    ushort endPort = 1024;
    uint count = 4;
    uint timeoutMs = 1000;
    uint concurrency = 1;
    uint durationSec = 10;
    uint intervalSec = 1;
    uint packetCount = 100;
    ulong rateLimit;
    ulong maxBps;
    ulong downloadBps;
    ulong uploadBps;
    int pid;
    bool promisc;
    bool json;
    bool verbose;
    double threshold;
    string[] positional;
}

public struct IpAddress
{
    string value;
    alias value this;
}

public struct MacAddress
{
    string value;
    alias value this;
}

public struct NetworkInterface
{
    string name;
    string address;
    MacAddress mac;
    uint mtu;
    ulong rxPackets;
    ulong txPackets;
    ulong rxBytes;
    ulong txBytes;
    ulong rxErrors;
    ulong txErrors;
    ulong rxDropped;
    ulong txDropped;
}

public struct Route
{
    string destination;
    string gateway;
    string mask;
    string interfaceName;
    uint metric;
}

public struct PingResult
{
    string host;
    string address;
    bool success;
    double latencyMs;
    string error;
}

public struct ScanResult
{
    string host;
    ushort port;
    bool open;
    string service;
    string banner;
    double latencyMs;
}

public struct DnsResult
{
    string hostname;
    string[] addresses;
    double responseTimeMs;
    bool success;
    string error;
}

public struct BandwidthStats
{
    string interfaceName;
    ulong rxBytes;
    ulong txBytes;
    ulong rxPackets;
    ulong txPackets;
    double rxMbps;
    double txMbps;
}

public struct FirewallRule
{
    string chain;
    string target;
    string protocol;
    string source;
    string destination;
    string options;
}

public struct MonitorSnapshot
{
    BandwidthStats current;
    BandwidthStats previous;
    double cpuUsage;
    double memoryUsage;
    uint connectionCount;
}

public struct StressResult
{
    ulong totalConnections;
    ulong successfulConnections;
    ulong failedConnections;
    ulong bytesSent;
    ulong bytesReceived;
    double minLatencyMs;
    double maxLatencyMs;
    double averageLatencyMs;
    double p50LatencyMs;
    double p95LatencyMs;
    double p99LatencyMs;
    double durationSec;
    double throughputMbps;
}

public immutable Duration defaultTimeout = dur!"seconds"(1);
