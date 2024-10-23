#ifndef PARSER_H
#define PARSER_H

#include <string>
#include <vector>
#include <set>
#include <cstdint>

extern std::set<std::string> supportedProtocols;

// 定义常见的协议
enum Protocol
{
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    FTP,
    DNS,
    SMTP,
    POP3,
    IMAP,
    SSH,
    Telnet,
    ARP,
    RARP,
    SCTP,
    IGMP,
    ESP,
    AH,
    OTHER
};

// 数据包信息结构
struct PacketInfo
{
    std::string time;          // 时间戳
    std::string sourceIP;      // 源IP
    std::string destinationIP; // 目的IP
    std::string protocol;      // 协议类型
    int sourcePort;            // 源端口
    int destinationPort;       // 目的端口
    int length;                // 数据包长度
    std::string info;          // 其他信息
};

// 以太网头部结构
struct EthernetHeader
{
    uint8_t destinationMAC[6]; // 目的MAC地址
    uint8_t sourceMAC[6];      // 源MAC地址
    uint16_t etherType;        // 上层协议类型 (IPv4, IPv6等)
};

// IPv4头部结构
struct IPv4Header
{
    uint8_t version_IHL;  // 版本号 + 头部长度
    uint8_t tos;          // 服务类型
    uint16_t totalLength; // 总长度
    uint16_t identification;
    uint16_t flags_fragmentOffset;
    uint8_t ttl;          // 生存时间
    uint8_t protocol;     // 协议类型 (TCP, UDP等)
    uint16_t headerChecksum;
    uint32_t sourceIP;      // 源IP地址
    uint32_t destinationIP; // 目的IP地址
};

// TCP头部结构
struct TCPHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgmentNumber;
    uint8_t dataOffset; // 4位数据偏移
    uint8_t flags;      // 6位标志
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
};

// UDP头部结构
struct UDPHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;
};

// DNS头部结构
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t questionCount;
    uint16_t answerCount;
    uint16_t authorityCount;
    uint16_t additionalCount;
};

// 协议节点结构，支持层级结构
struct ProtocolNode
{
    std::string protocolName;
    std::string details;
    std::vector<ProtocolNode> children;
};

// 协议解析器类
class ProtocolParser
{
public:
    ProtocolParser();

    // 解析数据包并写到packetInfo的接口
    void parsePacketLayers(PacketInfo &packetInfo, const unsigned char *packetData, int length, ProtocolNode &rootNode);

private:
    // 具体解析函数
    EthernetHeader parseEthernetHeader(const unsigned char *packetData);
    IPv4Header parseIPv4Header(const unsigned char *packetData);
    void parseIPv4Packet(PacketInfo &packetInfo, const unsigned char *packetData);
    TCPHeader parseTCPHeader(const unsigned char *packetData);
    void parseTCPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    UDPHeader parseUDPHeader(const unsigned char *packetData);
    void parseUDPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    DNSHeader parseDNSHeader(const unsigned char *packetData);
    void parseDNSPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    void parseHTTP(PacketInfo &packetInfo, const unsigned char *payload, int payloadSize);
};

#endif // PARSER_H
