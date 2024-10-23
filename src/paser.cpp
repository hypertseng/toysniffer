#include "parser.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>

std::set<std::string> supportedProtocols = {
    "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "DNS",
    "SMTP", "POP3", "IMAP", "SSH", "Telnet", "ARP",
    "RARP", "SCTP", "IGMP", "ESP", "AH"};

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

// 将IP地址转换为字符串
std::string ipToString(uint32_t ip)
{
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

// 解析IPv4头部
IPv4Header ProtocolParser::parseIPv4Header(const unsigned char *packetData)
{
    IPv4Header ipHeader;
    std::memcpy(&ipHeader, packetData, sizeof(IPv4Header));
    return ipHeader;
}

// 更新 PacketInfo
void ProtocolParser::parseIPv4Packet(PacketInfo &packetInfo, const unsigned char *packetData)
{
    IPv4Header ipHeader = parseIPv4Header(packetData);
    packetInfo.sourceIP = ipToString(ntohl(ipHeader.sourceIP));
    packetInfo.destinationIP = ipToString(ntohl(ipHeader.destinationIP));

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

// 解析TCP头部
TCPHeader ProtocolParser::parseTCPHeader(const unsigned char *packetData)
{
    TCPHeader tcpHeader;
    std::memcpy(&tcpHeader, packetData, sizeof(TCPHeader));
    return tcpHeader;
}

// 更新 PacketInfo
void ProtocolParser::parseTCPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    TCPHeader tcpHeader = parseTCPHeader(packetData);
    packetInfo.sourcePort = ntohs(tcpHeader.sourcePort);
    packetInfo.destinationPort = ntohs(tcpHeader.destinationPort);
    packetInfo.info = "Seq: " + std::to_string(ntohl(tcpHeader.sequenceNumber)) +
                      ", Ack: " + std::to_string(ntohl(tcpHeader.acknowledgmentNumber));
}

// 解析UDP头部
UDPHeader ProtocolParser::parseUDPHeader(const unsigned char *packetData)
{
    UDPHeader udpHeader;
    std::memcpy(&udpHeader, packetData, sizeof(UDPHeader));
    return udpHeader;
}

// 更新 PacketInfo
void ProtocolParser::parseUDPPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    UDPHeader udpHeader = parseUDPHeader(packetData);
    packetInfo.sourcePort = ntohs(udpHeader.sourcePort);
    packetInfo.destinationPort = ntohs(udpHeader.destinationPort);
    packetInfo.length = ntohs(udpHeader.length);
}

void ProtocolParser::parseHTTP(PacketInfo &packetInfo, const unsigned char *payload, int payloadSize)
{
    std::string httpPayload(reinterpret_cast<const char *>(payload), payloadSize);
    if (httpPayload.find("GET") == 0 || httpPayload.find("POST") == 0)
    {
        packetInfo.protocol = "HTTP";
        packetInfo.info = httpPayload.substr(0, httpPayload.find("\r\n"));
    }
}

// 解析DNS头部
DNSHeader ProtocolParser::parseDNSHeader(const unsigned char *packetData)
{
    DNSHeader dnsHeader;
    std::memcpy(&dnsHeader, packetData, sizeof(DNSHeader));
    return dnsHeader;
}

// 更新 PacketInfo
void ProtocolParser::parseDNSPacket(PacketInfo &packetInfo, const unsigned char *packetData)
{
    DNSHeader dnsHeader = parseDNSHeader(packetData);
    packetInfo.protocol = "DNS";
    packetInfo.info = "Queries: " + std::to_string(ntohs(dnsHeader.questionCount)) +
                      ", Answers: " + std::to_string(ntohs(dnsHeader.answerCount));
}

void ProtocolParser::parsePacketLayers(PacketInfo &packetInfo, const unsigned char *packetData, int length, ProtocolNode &rootNode)
{
    // 解析以太网层
    EthernetHeader ethHeader = parseEthernetHeader(packetData);
    int offset = sizeof(EthernetHeader); // 以太网头部大小
    ProtocolNode ethNode{"Ethernet", "Type: " + std::to_string(ntohs(ethHeader.etherType)), {}};
    rootNode.children.push_back(ethNode); // 添加到根节点

    // 判断上层协议 (IPv4 或 IPv6)
    if (ntohs(ethHeader.etherType) == 0x0800)
    {
        // IPv4
        parseIPv4Packet(packetInfo, packetData + offset);
        offset += sizeof(IPv4Header);

        ProtocolNode ipv4Node{"IPv4", "Source: " + packetInfo.sourceIP + ", Destination: " + packetInfo.destinationIP, {}};
        rootNode.children.back().children.push_back(ipv4Node); // 添加到以太网层

        // 判断传输层协议 (TCP 或 UDP)
        if (packetInfo.protocol == "TCP")
        {
            parseTCPPacket(packetInfo, packetData + offset);
            offset += sizeof(TCPHeader);

            ProtocolNode tcpNode{"TCP", "Src Port: " + std::to_string(packetInfo.sourcePort) + ", Dst Port: " + std::to_string(packetInfo.destinationPort), {}};
            rootNode.children.back().children.back().children.push_back(tcpNode); // 添加到 IPv4 层

            // 检查应用层协议 (HTTP)
            parseHTTP(packetInfo, packetData + offset, length - offset);
            if (!packetInfo.info.empty())
            {
                ProtocolNode httpNode{"HTTP", packetInfo.info, {}};
                rootNode.children.back().children.back().children.back().children.push_back(httpNode); // 添加到 TCP 层
            }
        }
        else if (packetInfo.protocol == "UDP")
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
        }
    }
}
