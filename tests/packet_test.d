import ripnet.network.packet;
import ripnet.network.target;
import std.algorithm : canFind;

int main()
{
    ubyte[] ethernet = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1,
        192, 0, 2, 2,
    ];
    EthernetFrame frame;
    assert(parseEthernet(ethernet, frame));
    assert(frame.etherType == 0x0800);
    assert(frame.payload.length == 20);

    IPv4Packet ip;
    assert(parseIpv4(frame.payload, ip));
    assert(ip.source == "192.0.2.1");
    assert(ip.destination == "192.0.2.2");
    assert(ip.protocol == 6);

    TransportPacket tcp;
    ubyte[] header = [0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0];
    assert(parseTransport(header, tcp));
    assert(tcp.sourcePort == 80);
    assert(tcp.destinationPort == 443);

    assert(!parseEthernet(ubyte[].init, frame));
    assert(!parseIpv4([0x60], ip));
    assert(isAddressLike("192.0.2.1"));
    assert(isAddressLike("example.com"));
    assert(isAddressLike("localhost"));
    assert(!isAddressLike("irfnhkjrfnnf"));
    assert(!isAddressLike("not a domain"));
    assert(!isAddressLike("999.0.2.1"));
    assert(invalidTargetMessage("irfnhkjrfnnf").canFind("invalid target format"));
    return 0;
}
