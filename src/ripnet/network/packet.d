module ripnet.network.packet;

public struct EthernetFrame
{
    ubyte[6] destination;
    ubyte[6] source;
    ushort etherType;
    ubyte[] payload;
}

public struct IPv4Packet
{
    string source;
    string destination;
    ubyte protocol;
    ubyte ttl;
    ubyte[] payload;
}

public struct TransportPacket
{
    ushort sourcePort;
    ushort destinationPort;
    ubyte[] payload;
}

public bool parseEthernet(const(ubyte)[] data, out EthernetFrame frame)
{
    if (data.length < 14)
        return false;
    frame.destination[] = data[0 .. 6];
    frame.source[] = data[6 .. 12];
    frame.etherType = (cast(ushort) data[12] << 8) | data[13];
    frame.payload = cast(ubyte[]) data[14 .. $];
    return true;
}

public bool parseIpv4(const(ubyte)[] data, out IPv4Packet packet)
{
    if (data.length < 20 || (data[0] >> 4) != 4)
        return false;
    auto headerLength = (data[0] & 0x0f) * 4;
    if (headerLength < 20 || data.length < headerLength)
        return false;
    packet.ttl = data[8];
    packet.protocol = data[9];
    packet.source = address(data[12 .. 16]);
    packet.destination = address(data[16 .. 20]);
    packet.payload = cast(ubyte[]) data[headerLength .. $];
    return true;
}

private string address(const(ubyte)[] bytes)
{
    import std.format : format;

    return format("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

public bool parseTransport(const(ubyte)[] data, out TransportPacket packet)
{
    if (data.length < 8)
        return false;
    packet.sourcePort = (cast(ushort) data[0] << 8) | data[1];
    packet.destinationPort = (cast(ushort) data[2] << 8) | data[3];
    auto headerLength = data.length >= 20 ? ((data[12] >> 4) * 4) : 8;
    if (headerLength > data.length)
        headerLength = 8;
    packet.payload = cast(ubyte[]) data[headerLength .. $];
    return true;
}
