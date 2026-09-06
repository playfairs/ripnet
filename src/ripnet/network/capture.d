module ripnet.network.capture;

import ripnet.network.packet;
import std.string : toStringz, fromStringz, strip, startsWith;
import std.stdio : writefln, writeln;

extern (C)
{
    struct pcap_t;
    struct timeval
    {
        long tv_sec;
        long tv_usec;
    }

    struct pcap_pkthdr
    {
        timeval ts;
        uint caplen;
        uint len;
    }

    pcap_t* pcap_open_live(const(char)* device, int snaplen, int promisc,
            int timeoutMs, char* errorBuffer);
    int pcap_next_ex(pcap_t* handle, pcap_pkthdr** header, const(ubyte)** data);
    const(char)* pcap_geterr(pcap_t* handle);
    void pcap_close(pcap_t* handle);
}

public int capture(string interfaceName, string filter, uint count, bool promisc)
{
    char[256] errorBuffer;
    auto handle = pcap_open_live(interfaceName.toStringz, 65535, promisc ? 1 : 0,
            1000, errorBuffer.ptr);
    if (handle is null)
    {
        writeln("capture: ", cleanError(fromStringz(errorBuffer.ptr)));
        return -1;
    }
    scope (exit)
        pcap_close(handle);

    uint captured;
    while (captured < count)
    {
        pcap_pkthdr* header;
        const(ubyte)* data;
        auto status = pcap_next_ex(handle, &header, &data);
        if (status == 0)
            continue;
        if (status < 0)
        {
            writeln("capture: ", cleanError(fromStringz(pcap_geterr(handle))));
            return -1;
        }
        auto bytes = data[0 .. header.caplen];
        EthernetFrame frame;
        if (parseEthernet(bytes, frame))
            writefln("%s -> %s type=0x%04x length=%d", hex(frame.source),
                    hex(frame.destination), frame.etherType, header.len);
        else
            writefln("packet length=%d", header.len);
        ++captured;
    }
    return 0;
}

private string cleanError(const(char)[] message)
{
    auto cleaned = message.strip.idup;
    if (cleaned.startsWith(":"))
        cleaned = cleaned[1 .. $].strip;
    return cleaned;
}

private string hex(ubyte[6] address)
{
    import std.format : format;

    return format("%02x:%02x:%02x:%02x:%02x:%02x", address[0], address[1],
            address[2], address[3], address[4], address[5]);
}
