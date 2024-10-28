#include "parser.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>

std::set<std::string> supportedProtocols = {
    "TCP",
    "UDP",
    "ICMP",
    "HTTP",
    "HTTPS",
    "DNS",
    "RIP",
    "ARP",
    "IGMP",
};

ProtocolParser::ProtocolParser() {}

// 将 MAC 地址格式化为人类可读的字符串
std::string macToString(const uint8_t mac[6])
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i)
    {
        oss << std::setw(2) << static_cast<int>(mac[i]);
        if (i != 5)
            oss << ":";
    }
    return oss.str();
}

// 解析以太网头部
EthernetHeader ProtocolParser::parseEthernetHeader(const unsigned char *packetData)
{
    EthernetHeader ethHeader;
    std::memcpy(&ethHeader, packetData, sizeof(EthernetHeader));
    return ethHeader;
}

// 解析IPv4头部
IPv4Header ProtocolParser::parseIPv4Header(const unsigned char *packetData)
{
    IPv4Header ipHeader;
    std::memcpy(&ipHeader, packetData, sizeof(IPv4Header));
    return ipHeader;
}

// 将IPv4地址转换为字符串
std::string ipToString(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

// 更新 PacketInfo
void ProtocolParser::parseIPv4Packet(PacketInfo &packetInfo, const unsigned char *packetData)
{
    IPv4Header ipHeader = parseIPv4Header(packetData);
    packetInfo.sourceIP = ipToString(ntohl(ipHeader.sourceIP));
    packetInfo.destinationIP = ipToString(ntohl(ipHeader.destinationIP));
    packetInfo.info = std::string("IPv4 Packet: ") +
                      "Source: " + packetInfo.sourceIP +
                      ", Destination: " + packetInfo.destinationIP +
                      ", Protocol: " + std::to_string(ipHeader.protocol) +
                      ", Total Length: " + std::to_string(ntohs(ipHeader.totalLength));

    // 检查上层协议类型
    switch (ipHeader.protocol)
    {
    case 0x06:
        packetInfo.protocol = "TCP";
        break;
    case 0x11:
        packetInfo.protocol = "UDP";
        break;
    default:
        packetInfo.protocol = "Unknown";
        break;
    }

    packetInfo.length = ntohs(ipHeader.totalLength);
}

// 解析IPv6头部
IPv6Header ProtocolParser::parseIPv6Header(const unsigned char *packetData)
{
    IPv6Header ipv6Header;
    std::memcpy(&ipv6Header, packetData, sizeof(IPv6Header));
    return ipv6Header;
}

// 将IPv6地址转换为字符串
std::string ipv6ToString(const uint8_t ip[16])
{
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, buffer, sizeof(buffer));
    return std::string(buffer);
}

// 解析 IPv6 扩展头部的函数
IPv6ExtensionHeader ProtocolParser::parseIPv6ExtensionHeader(const unsigned char *packetData)
{
    IPv6ExtensionHeader extHeader;
    std::memcpy(&extHeader, packetData, sizeof(IPv6ExtensionHeader));
    return extHeader;
}

// IPv6数据包解析，包括扩展头部
void ProtocolParser::parseIPv6Packet(PacketInfo &packetInfo, const unsigned char *packetData, int &offset, ProtocolNode &ipv6Node)
{
    IPv6Header ipv6Header = parseIPv6Header(packetData + offset);
    packetInfo.sourceIP = ipv6ToString(ipv6Header.sourceIP);
    packetInfo.destinationIP = ipv6ToString(ipv6Header.destinationIP);
    packetInfo.length = ntohs(ipv6Header.payloadLength);
    packetInfo.info = std::string("IPv6 Packet: ") +
                      "Source: " + packetInfo.sourceIP +
                      ", Destination: " + packetInfo.destinationIP +
                      ", Payload Length: " + std::to_string(ntohs(ipv6Header.payloadLength)) +
                      ", Next Header: " + std::to_string(ipv6Header.nextHeader);

    ipv6Node.protocolName = "IPv6";
    ipv6Node.details = "Source: " + packetInfo.sourceIP + ", Destination: " + packetInfo.destinationIP;

    uint8_t nextHeader = ipv6Header.nextHeader;
    offset += sizeof(IPv6Header);

    // 逐步解析IPv6扩展头部
    while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 || nextHeader == 60)
    {
        IPv6ExtensionHeader extHeader = parseIPv6ExtensionHeader(packetData + offset);
        ProtocolNode extNode;

        switch (nextHeader)
        {
        case 0: // Hop-by-Hop Options Header
            extNode.protocolName = "IPv6 Hop-by-Hop Options";
            extNode.details = "Options Length: " + std::to_string(extHeader.hdrExtLen * 8);
            break;
        case 43: // Routing Header
            extNode.protocolName = "Routing Header";
            extNode.details = "Length: " + std::to_string(extHeader.hdrExtLen * 8);
            break;
        case 44: // Fragment Header
            extNode.protocolName = "Fragment Header";
            extNode.details = "Fragmented Packet";
            break;
        case 51: // Authentication Header
            extNode.protocolName = "Authentication Header";
            extNode.details = "AH Length: " + std::to_string(extHeader.hdrExtLen * 8);
            break;
        case 60: // Destination Options Header
            extNode.protocolName = "Destination Options Header";
            extNode.details = "Options Length: " + std::to_string(extHeader.hdrExtLen * 8);
            break;
        default:
            extNode.protocolName = "Unknown Extension Header";
            extNode.details = "Type: " + std::to_string(nextHeader);
            break;
        }

        // 添加扩展头部节点到IPv6节点
        ipv6Node.children.push_back(extNode);

        // 更新 offset 和 nextHeader
        nextHeader = extHeader.nextHeader;
        offset += (extHeader.hdrExtLen + 1) * 8;
    }

    // 解析上层协议
    switch (nextHeader)
    {
    case IPPROTO_TCP:
        parseTCPPacket(packetInfo, packetData + offset);
        ipv6Node.children.push_back({"TCP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}});
        break;
    case IPPROTO_UDP:
        parseUDPPacket(packetInfo, packetData + offset);
        ipv6Node.children.push_back({"UDP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}});
        break;
    case IPPROTO_ICMPV6:
        parseICMPPacket(packetInfo, packetData + offset);
        ipv6Node.children.push_back({"ICMPv6", packetInfo.info, {}});
        break;
    default:
        ipv6Node.children.push_back({"Unknown Protocol", "Protocol not recognized", {}});
        break;
    }
}

// ARP数据包解析
// ARP数据包解析
void ProtocolParser::parseARPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    ARPHeader arpHeader = parseARPHeader(packetData);
    packetInfo.protocol = "ARP";
    packetInfo.sourceIP = ipToString(ntohl(arpHeader.senderIP));
    packetInfo.destinationIP = ipToString(ntohl(arpHeader.targetIP));

    packetInfo.info = std::string("ARP Packet: ") +
                      "Opcode: " + std::to_string(ntohs(arpHeader.opcode)) +
                      ", Sender MAC: " + macToString(arpHeader.senderMAC) +
                      ", Sender IP: " + packetInfo.sourceIP +
                      ", Target MAC: " + macToString(arpHeader.targetMAC) +
                      ", Target IP: " + packetInfo.destinationIP;
}

ARPHeader ProtocolParser::parseARPHeader(const unsigned char *packetData)
{
    ARPHeader arpHeader;
    // 假设 packetData 指向 ARP 数据包的起始位置
    memcpy(&arpHeader, packetData, sizeof(ARPHeader));
    return arpHeader;
}

RIPHeader ProtocolParser::parseRIPHeader(const unsigned char *packetData)
{
    RIPHeader ripHeader;
    std::memcpy(&ripHeader, packetData, sizeof(RIPHeader));
    return ripHeader;
}

RouteEntry ProtocolParser::parseRouteEntry(const unsigned char *packetData)
{
    RouteEntry entry;

    // 假设路由条目结构是固定的，并根据 RIP v2 的定义进行解析
    // RIP v2 路由条目的格式为：
    // |  Destination IP (4 bytes) |  Metric (4 bytes)  |
    // |-----------------------------|---------------------|

    // 解析目标地址（4字节）
    entry.destination = ntohl(*(uint32_t *)packetData); // 将网络字节序转换为主机字节序
    packetData += sizeof(uint32_t);                     // 移动到下一个字段

    // 解析度量值（4字节）
    entry.metric = ntohl(*(uint32_t *)packetData); // 将网络字节序转换为主机字节序

    return entry;
}

// RIP数据包解析
void ProtocolParser::parseRIPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    RIPHeader ripHeader = parseRIPHeader(packetData);
    packetInfo.protocol = "RIP";

    // 解析 RIP 数据包的字段
    packetInfo.info = "Version: " + std::to_string(ripHeader.version) +
                      ", Command: " + std::to_string(ripHeader.command) +
                      ", Entries: " + std::to_string(ntohs(ripHeader.entryCount));

    // 处理每个路由条目
    for (int i = 0; i < ntohs(ripHeader.entryCount); ++i)
    {
        // 假设你有一个函数解析单个路由条目，下面是伪代码
        RouteEntry entry = parseRouteEntry(packetData + sizeof(RIPHeader) + i * sizeof(RouteEntry));
        packetInfo.info += "\nRoute Entry " + std::to_string(i + 1) + ": " +
                           "Destination: " + ipToString(entry.destination) +
                           ", Metric: " + std::to_string(entry.metric);
    }
}

// 解析TCP头部
TCPHeader ProtocolParser::parseTCPHeader(const unsigned char *packetData)
{
    TCPHeader tcpHeader;
    std::memcpy(&tcpHeader, packetData, sizeof(TCPHeader));
    return tcpHeader;
}

void ProtocolParser::parseTCPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    TCPHeader tcpHeader = parseTCPHeader(packetData);
    packetInfo.sourcePort = ntohs(tcpHeader.sourcePort);
    packetInfo.destinationPort = ntohs(tcpHeader.destinationPort);

    packetInfo.info = std::string("TCP Packet: ") +
                      "Source Port: " + std::to_string(packetInfo.sourcePort) +
                      ", Destination Port: " + std::to_string(packetInfo.destinationPort) +
                      ", Sequence Number: " + std::to_string(ntohl(tcpHeader.sequenceNumber)) +
                      ", Acknowledgment Number: " + std::to_string(ntohl(tcpHeader.acknowledgmentNumber)) +
                      ", Flags: " + std::to_string(tcpHeader.flags);
}

// 解析UDP头部
UDPHeader ProtocolParser::parseUDPHeader(const unsigned char *packetData)
{
    UDPHeader udpHeader;
    std::memcpy(&udpHeader, packetData, sizeof(UDPHeader));
    return udpHeader;
}

void ProtocolParser::parseUDPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    UDPHeader udpHeader = parseUDPHeader(packetData);
    packetInfo.sourcePort = ntohs(udpHeader.sourcePort);
    packetInfo.destinationPort = ntohs(udpHeader.destinationPort);

    packetInfo.info = std::string("UDP Packet: ") +
                      "Source Port: " + std::to_string(packetInfo.sourcePort) +
                      ", Destination Port: " + std::to_string(packetInfo.destinationPort) +
                      ", Length: " + std::to_string(ntohs(udpHeader.length));
}

// 解析ICMP头部
ICMPHeader ProtocolParser::parseICMPHeader(const unsigned char *packetData)
{
    ICMPHeader icmpHeader;
    std::memcpy(&icmpHeader, packetData, sizeof(ICMPHeader));
    return icmpHeader;
}

void ProtocolParser::parseICMPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    ICMPHeader icmpHeader = parseICMPHeader(packetData);
    packetInfo.protocol = "ICMP";
    packetInfo.info = std::string("ICMP Packet: ") +
                      "Type: " + std::to_string(icmpHeader.type) +
                      ", Code: " + std::to_string(icmpHeader.code) +
                      ", Checksum: " + std::to_string(ntohs(icmpHeader.checksum));
}

// 解析IGMP头部
IGMPHeader ProtocolParser::parseIGMPHeader(const unsigned char *packetData)
{
    IGMPHeader igmpHeader;
    std::memcpy(&igmpHeader, packetData, sizeof(IGMPHeader));
    return igmpHeader;
}

// 更新 PacketInfo
void ProtocolParser::parseIGMPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    IGMPHeader igmpHeader = parseIGMPHeader(packetData);
    packetInfo.protocol = "IGMP";
    packetInfo.info = "Type: " + std::to_string(igmpHeader.type) + ", Group Address: " + ipToString(ntohl(igmpHeader.groupAddress));
}

bool ProtocolParser::isHTTPPayload(const unsigned char *payload, int length)
{
    if (length <= 0)
        return false;

    // 检查请求行
    std::string requestLine(reinterpret_cast<const char *>(payload), length);
    return requestLine.find("GET ") != std::string::npos ||
           requestLine.find("POST ") != std::string::npos ||
           requestLine.find("PUT ") != std::string::npos ||
           requestLine.find("DELETE ") != std::string::npos ||
           requestLine.find("HTTP/") != std::string::npos;
}

void ProtocolParser::parseHTTP(PacketInfo &packetInfo, const unsigned char *payload, int payloadSize)
{
    std::string httpPayload(reinterpret_cast<const char *>(payload), payloadSize);

    // 检查是否是 HTTP 请求
    if (httpPayload.find("GET") == 0 || httpPayload.find("POST") == 0)
    {
        packetInfo.protocol = "HTTP";

        // 提取请求行
        size_t requestLineEnd = httpPayload.find("\r\n");
        if (requestLineEnd != std::string::npos)
        {
            std::string requestLine = httpPayload.substr(0, requestLineEnd);
            size_t methodEnd = requestLine.find(' '); // 查找第一个空格
            if (methodEnd != std::string::npos)
            {
                packetInfo.info = requestLine;                         // 保存请求行
                size_t pathEnd = requestLine.find(' ', methodEnd + 1); // 查找第二个空格
                if (pathEnd != std::string::npos)
                {
                    // 提取方法、路径和版本
                    std::string method = requestLine.substr(0, methodEnd);                         // 方法
                    std::string path = requestLine.substr(methodEnd + 1, pathEnd - methodEnd - 1); // 请求路径
                    std::string version = requestLine.substr(pathEnd + 1);                         // HTTP 版本

                    // 可以选择将这些信息保存到 packetInfo 中的其他字段
                    packetInfo.info = "Method: " + method + ", Path: " + path + ", Version: " + version;

                    // 解析请求头
                    size_t headersStart = requestLineEnd + 2; // 跳过请求行后的 CRLF
                    size_t headersEnd = httpPayload.find("\r\n\r\n", headersStart);
                    if (headersEnd != std::string::npos)
                    {
                        std::string headers = httpPayload.substr(headersStart, headersEnd - headersStart);
                        // 进一步处理请求头，如果需要
                    }

                    // 处理请求体（如果存在）
                    int bodyStart = headersEnd + 4; // 跳过请求头后的 CRLF
                    if (bodyStart < payloadSize)
                    {
                        std::string body = httpPayload.substr(bodyStart);
                        // 可以选择保存请求体的信息
                    }
                }
            }
        }
    }
}

// 解析DNS头部
DNSHeader ProtocolParser::parseDNSHeader(const unsigned char *packetData)
{
    DNSHeader dnsHeader;
    std::memcpy(&dnsHeader, packetData, sizeof(DNSHeader));
    return dnsHeader;
}

void ProtocolParser::parseDNSPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    DNSHeader dnsHeader = parseDNSHeader(packetData);
    packetInfo.protocol = "DNS";

    packetInfo.info = std::string("DNS Packet: ") +
                      "Queries: " + std::to_string(ntohs(dnsHeader.questionCount)) +
                      ", Answers: " + std::to_string(ntohs(dnsHeader.answerCount)) +
                      ", Authority Records: " + std::to_string(ntohs(dnsHeader.authorityCount)) +
                      ", Additional Records: " + std::to_string(ntohs(dnsHeader.additionalCount));
}

void ProtocolParser::parsePacketLayers(PacketInfo &packetInfo, const unsigned char *packetData, int length, ProtocolNode &rootNode)
{
    // 解析以太网层
    EthernetHeader ethHeader = parseEthernetHeader(packetData);
    int offset = sizeof(EthernetHeader); // 以太网头部大小
    ProtocolNode ethNode{"Ethernet Frame:", std::string("Source MAC: ") + macToString(ethHeader.sourceMAC) + ", Destination MAC: " + macToString(ethHeader.destinationMAC) + ", EtherType: " + std::to_string(ntohs(ethHeader.etherType)), {}};
    rootNode.children.push_back(ethNode); // 添加到根节点

    // 判断上层协议 (IPv4 或 IPv6)
    switch (ntohs(ethHeader.etherType))
    {
    case 0x0800: // IPv4
    {
        parseIPv4Packet(packetInfo, packetData + offset);
        offset += sizeof(IPv4Header);

        ProtocolNode ipv4Node{"IPv4", "Source: " + packetInfo.sourceIP + ", Destination: " + packetInfo.destinationIP, {}};
        rootNode.children.back().children.push_back(ipv4Node); // 添加到以太网层

        // 判断传输层协议 (TCP、UDP、ICMP 或 IGMP)
        switch (packetInfo.protocol[0]) // 以协议首字母区分 TCP、UDP、ICMP 和 IGMP
        {
        case 'T': // TCP
        {
            parseTCPPacket(packetInfo, packetData + offset);
            offset += sizeof(TCPHeader);

            ProtocolNode tcpNode{"TCP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}};
            rootNode.children.back().children.back().children.push_back(tcpNode); // 添加到 IPv4 层

            // 检查是否为 HTTP
            if (packetInfo.sourcePort == 80 || packetInfo.destinationPort == 80)
            {
                const unsigned char *payload = packetData + offset;
                int payloadLength = length - offset;

                // 检查是否包含 HTTP 请求
                if (isHTTPPayload(payload, payloadLength))
                {
                    parseHTTP(packetInfo, payload, payloadLength);
                    if (!packetInfo.info.empty())
                    {
                        ProtocolNode httpNode{"HTTP", packetInfo.info, {}};
                        rootNode.children.back().children.back().children.back().children.push_back(httpNode); // 添加到 TCP 层
                    }
                }
            }
            break;
        }
        case 'U': // UDP
        {
            parseUDPPacket(packetInfo, packetData + offset);

            ProtocolNode udpNode{"UDP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}};
            rootNode.children.back().children.back().children.push_back(udpNode); // 添加到 IPv4 层

            // 检查应用层协议 (DNS)
            if (packetInfo.destinationPort == 53 || packetInfo.sourcePort == 53)
            {
                parseDNSPacket(packetInfo, packetData + offset);
                ProtocolNode dnsNode{"DNS", packetInfo.info, {}};
                rootNode.children.back().children.back().children.back().children.push_back(dnsNode); // 添加到 UDP 层
            }
            break;
        }
        case 'I': // ICMP
        {
            parseICMPPacket(packetInfo, packetData + offset);
            ProtocolNode icmpNode{"ICMP", "Type: " + packetInfo.info, {}};
            rootNode.children.back().children.push_back(icmpNode); // 添加到 IPv4 层
            break;
        }
        case 'G': // IGMP
        {
            parseIGMPPacket(packetInfo, packetData + offset);
            ProtocolNode igmpNode{"IGMP", "Type: " + packetInfo.info, {}};
            rootNode.children.back().children.push_back(igmpNode); // 添加到 IPv4 层
            break;
        }
        case 'R': // RIP
        {
            parseRIPPacket(packetInfo, packetData + offset); // 解析 RIP 数据包

            ProtocolNode ripNode{"RIP", "Version: " + std::to_string(packetInfo.length), {}};
            ipv4Node.children.push_back(ripNode); // 添加到 IPv4 节点

            // 解析 RIP 路由条目
            const unsigned char *ripData = packetData + offset;
            int ripLength = length - offset;
            while (ripLength > 0)
            {
                RouteEntry routeEntry = parseRouteEntry(ripData); // 解析单个路由条目
                ProtocolNode routeNode{"Route", "Destination: " + std::to_string(routeEntry.destination) + ", Metric: " + std::to_string(routeEntry.metric), {}};
                ripNode.children.push_back(routeNode); // 添加路由条目到 RIP 节点

                // 更新 RIP 数据偏移量和剩余长度
                ripData += sizeof(RouteEntry);
                ripLength -= sizeof(RouteEntry);
            }
            break;
        }
        default: // 未知协议
            ProtocolNode unknownNode{"Unknown Protocol", "Protocol not recognized", {}};
            rootNode.children.back().children.push_back(unknownNode);
            break;
        }
        break;
    }

    case 0x0806: // ARP
    {
        ARPHeader arpHeader = parseARPHeader(packetData + offset); // 解析 ARP 头部
        ProtocolNode arpNode{"ARP", "Operation: " + std::to_string(ntohs(arpHeader.opcode)), {}};
        rootNode.children.push_back(arpNode); // 添加到以太网层

        // 更新 PacketInfo 结构体信息
        packetInfo.protocol = "ARP";
        packetInfo.sourceIP = ipToString(ntohl(arpHeader.senderIP));      // 将 IP 从网络字节序转换为字符串
        packetInfo.destinationIP = ipToString(ntohl(arpHeader.targetIP)); // 将 IP 从网络字节序转换为字符串
        packetInfo.sourcePort = -1;                                       // ARP 没有端口概念
        packetInfo.destinationPort = -1;
        packetInfo.length = sizeof(ARPHeader); // 更新数据包长度
        packetInfo.info = "Sender MAC: " + macToString(arpHeader.senderMAC) +
                          ", Target MAC: " + macToString(arpHeader.targetMAC);

        // 进一步解析 ARP 数据包内容
        ProtocolNode arpEntryNode{
            "ARP Entry",
            "Sender IP: " + packetInfo.sourceIP +
                ", Sender MAC: " + macToString(arpHeader.senderMAC) +
                ", Target IP: " + packetInfo.destinationIP +
                ", Target MAC: " + macToString(arpHeader.targetMAC),
            {}};
        arpNode.children.push_back(arpEntryNode); // 添加到 ARP 节点
        break;
    }

    case 0x86DD: // IPv6
    {
        ProtocolNode ipv6Node{"IPv6", "Source: " + packetInfo.sourceIP + ", Destination: " + packetInfo.destinationIP, {}};
        parseIPv6Packet(packetInfo, packetData, offset, ipv6Node);
        rootNode.children.back().children.push_back(ipv6Node); // 添加到以太网层

        // 逐步解析 IPv6 扩展头
        int nextHeader = packetInfo.protocol[0];
        bool done = false;

        while (!done)
        {
            IPv6ExtensionHeader extHeader = parseIPv6ExtensionHeader(packetData + offset);
            ProtocolNode extNode;

            // 根据 nextHeader 类型解析不同的 IPv6 扩展头
            switch (nextHeader)
            {
            case 0: // Hop-by-Hop Option Header
                extNode.protocolName = "IPv6 Hop-by-Hop Options";
                extNode.details = "Options Length: " + std::to_string(extHeader.hdrExtLen * 8);
                break;
            case 43: // Routing Header
                extNode.protocolName = "Routing Header";
                extNode.details = "Length: " + std::to_string(extHeader.hdrExtLen * 8);
                break;
            case 44: // Fragment Header
                extNode.protocolName = "Fragment Header";
                extNode.details = "Fragmented Packet";
                break;
            case 51: // Authentication Header
                extNode.protocolName = "Authentication Header";
                extNode.details = "AH Length: " + std::to_string(extHeader.hdrExtLen * 8);
                break;
            case 60: // Destination Options Header
                extNode.protocolName = "Destination Options Header";
                extNode.details = "Options Length: " + std::to_string(extHeader.hdrExtLen * 8);
                break;
            default: // 未知扩展头
                extNode.protocolName = "Unknown Extension Header";
                extNode.details = "Type: " + std::to_string(nextHeader);
                done = true; // 未知协议，停止解析扩展头链
                break;
            }

            // 将扩展头节点添加到 IPv6 节点的子节点
            ipv6Node.children.push_back(extNode);

            // 更新 nextHeader，继续解析链中的下一个扩展头
            nextHeader = extHeader.nextHeader;
            offset += (extHeader.hdrExtLen + 1) * 8;

            // 解析到非扩展头协议时，停止解析
            if (nextHeader != 0 && nextHeader != 43 && nextHeader != 44 && nextHeader != 51 && nextHeader != 60)
            {
                done = true;
            }
        }

        // 处理上层协议 (TCP、UDP 或 ICMPv6)
        switch (nextHeader)
        {
        case IPPROTO_TCP:
        {
            parseTCPPacket(packetInfo, packetData + offset);
            ProtocolNode tcpNode{"TCP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}};
            ipv6Node.children.push_back(tcpNode); // 添加到 IPv6 节点

            // 检查是否为 HTTP
            if (packetInfo.sourcePort == 80 || packetInfo.destinationPort == 80)
            {
                const unsigned char *payload = packetData + offset;
                int payloadLength = length - offset;

                // 检查是否包含 HTTP 请求
                if (isHTTPPayload(payload, payloadLength))
                {
                    parseHTTP(packetInfo, payload, payloadLength);
                    if (!packetInfo.info.empty())
                    {
                        ProtocolNode httpNode{"HTTP", packetInfo.info, {}};
                        rootNode.children.back().children.back().children.back().children.push_back(httpNode); // 添加到 TCP 层
                    }
                }
            }
            break;
        }
        case IPPROTO_UDP:
        {
            parseUDPPacket(packetInfo, packetData + offset);
            ProtocolNode udpNode{"UDP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}};
            ipv6Node.children.push_back(udpNode); // 添加到 IPv6 节点

            // 检查是否是 DNS
            if (packetInfo.destinationPort == 53 || packetInfo.sourcePort == 53)
            {
                parseDNSPacket(packetInfo, packetData + offset);
                ProtocolNode dnsNode{"DNS", packetInfo.info, {}};
                ipv6Node.children.back().children.push_back(dnsNode); // 添加到 UDP 节点
            }
            break;
        }
        case IPPROTO_ICMPV6:
        {
            parseICMPPacket(packetInfo, packetData + offset);
            ProtocolNode icmpNode{"ICMPv6", packetInfo.info, {}};
            ipv6Node.children.push_back(icmpNode); // 添加到 IPv6 节点
            break;
        }
        default: // 未知协议
            ProtocolNode unknownNode{"Unknown Protocol", "Protocol not recognized", {}};
            ipv6Node.children.push_back(unknownNode);
            break;
        }
        break;
    }

    default: // 其他以太网类型
        ProtocolNode unknownEthNode{"Unknown Ethernet Type", "Ethernet type not recognized", {}};
        rootNode.children.push_back(unknownEthNode);
        break;
    }
}
