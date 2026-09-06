module ripnet.network.target;

import std.algorithm : all;
import std.conv : to;
import std.string : split, indexOf;

public bool isAddressLike(string target)
{
    if (target.length == 0 || target.length > 253)
        return false;
    if (target == "localhost")
        return true;
    if (target.indexOf(':') >= 0)
        return validIpv6Shape(target);
    if (target.indexOf('.') >= 0 && validIpv4Shape(target))
        return true;
    if (target.indexOf('.') < 0)
        return false;

    auto labels = target.split('.');
    if (labels.length == 4 && labels.all!((label) => label.length > 0
            && label.all!((character) => character >= '0' && character <= '9')))
        return false;
    foreach (label; labels)
    {
        if (label.length == 0 || label.length > 63 || label[0] == '-' || label[$ - 1] == '-')
            return false;
        foreach (character; label)
            if (!isHostnameCharacter(character))
                return false;
    }
    return true;
}

public string invalidTargetMessage(string target)
{
    return "invalid target format: '" ~ target ~ "' is not an IP address or domain name";
}

private bool validIpv4Shape(string target)
{
    auto octets = target.split('.');
    if (octets.length != 4)
        return false;
    foreach (octet; octets)
    {
        if (octet.length == 0 || (octet.length > 1 && octet[0] == '0'))
            return false;
        try
        {
            if (to!uint(octet) > 255)
                return false;
        }
        catch (Exception)
            return false;
    }
    return true;
}

private bool validIpv6Shape(string target)
{
    bool hasHexDigit;
    foreach (character; target)
    {
        if (character == ':')
            continue;
        if (!isHexDigit(character))
            return false;
        hasHexDigit = true;
    }
    return hasHexDigit;
}

private bool isHostnameCharacter(char character)
{
    return isAsciiLetter(character) || (character >= '0' && character <= '9') || character == '-';
}

private bool isAsciiLetter(char character)
{
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
}

private bool isHexDigit(char character)
{
    return (character >= 'a' && character <= 'f') || (character >= 'A'
            && character <= 'F') || (character >= '0' && character <= '9');
}
