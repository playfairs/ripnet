import ripnet.network.scan : networkScan;
import ripnet.network.target : ipv4CidrError, parseIpv4Cidr;

int main()
{
    uint address;
    uint prefix;
    assert(parseIpv4Cidr("192.0.2.3/30", address, prefix));
    assert(address == 0xc0000203);
    assert(prefix == 30);

    assert(!parseIpv4Cidr("192.0.2.256/24", address, prefix));
    assert(!parseIpv4Cidr("192.0.2.1/nope", address, prefix));
    assert(ipv4CidrError("192.0.2.0/12").length > 0);
    assert(ipv4CidrError("192.0.2.0/20").length == 0);

    auto pointToPoint = networkScan("192.0.2.2/31");
    assert(pointToPoint.length == 2);
    assert(pointToPoint[0].host == "192.0.2.2");
    assert(pointToPoint[1].host == "192.0.2.3");

    auto singleHost = networkScan("192.0.2.2/32");
    assert(singleHost.length == 1);
    assert(singleHost[0].host == "192.0.2.2");

    auto subnet = networkScan("192.0.2.3/30");
    assert(subnet.length == 2);
    assert(subnet[0].host == "192.0.2.1");
    assert(subnet[1].host == "192.0.2.2");
    assert(networkScan("192.0.2.0/nope").length == 0);
    return 0;
}
