#ifndef PARSER_H
#define PARSER_H

#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include "capture.h"

extern std::set<std::string> supportedProtocols;

// 定义常见的协议
enum Protocol
{
    TCP,
    UDP,
    ICMP, // 添加ICMP
    HTTP,
    HTTPS,
    DNS,
    ARP,
    RIP,
    IGMP, // 添加IGMP
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
    uint8_t ttl;      // 生存时间
    uint8_t protocol; // 协议类型 (TCP, UDP等)
    uint16_t headerChecksum;
    uint32_t sourceIP;      // 源IP地址
    uint32_t destinationIP; // 目的IP地址
};

// IPv6头部结构
struct IPv6Header
{
    uint32_t versionTrafficClassFlowLabel; // 版本 + 流量类别 + 流标签
    uint16_t payloadLength;                // 有效载荷长度
    uint8_t nextHeader;                    // 下一个头部协议类型
    uint8_t hopLimit;                      // 跳数限制
    uint8_t sourceIP[16];                  // 源IP地址
    uint8_t destinationIP[16];             // 目的IP地址
};

struct IPv6ExtensionHeader
{
    uint8_t nextHeader;
    uint8_t hdrExtLen;
    // 扩展头部的其他字段根据不同类型扩展
};

// ARP头部结构
struct ARPHeader
{
    uint16_t hardwareType; // 硬件类型
    uint16_t protocolType; // 协议类型
    uint8_t hardwareSize;  // 硬件地址长度
    uint8_t protocolSize;  // 协议地址长度
    uint16_t opcode;       // 操作码
    uint8_t senderMAC[6];  // 发送者 MAC 地址
    uint32_t senderIP;     // 发送者 IP 地址
    uint8_t targetMAC[6];  // 目标 MAC 地址
    uint32_t targetIP;     // 目标 IP 地址
};

// RIP 路由条目定义
struct RouteEntry
{
    uint32_t destination; // 目的地地址
    uint32_t metric;      // 路由度量值
    // 其他字段可以根据需要添加
};

// RIP 头部定义
struct RIPHeader
{
    uint8_t command;     // 命令（请求/应答）
    uint8_t version;     // 版本
    uint16_t entryCount; // 路由条目数
    // 其他字段可以根据需要添加
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

// ICMP头部结构
struct ICMPHeader
{
    uint8_t type;          // ICMP类型
    uint8_t code;          // ICMP代码
    uint16_t checksum;     // 校验和
    uint32_t restOfHeader; // 其余头部内容
};

// IGMP头部结构
struct IGMPHeader
{
    uint8_t type;            // IGMP类型
    uint8_t maxResponseTime; // 最大响应时间
    uint16_t checksum;       // 校验和
    uint32_t groupAddress;   // 组地址
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

struct DataNode
{
    int length;
    const u_char *data;
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
    IPv6Header parseIPv6Header(const unsigned char *packetData); // 添加 IPv6 解析函数
    ARPHeader parseARPHeader(const unsigned char *packetData);
    RIPHeader parseRIPHeader(const unsigned char *packetData);
    ICMPHeader parseICMPHeader(const unsigned char *packetData);
    IGMPHeader parseIGMPHeader(const unsigned char *packetData); // 添加 IPv6 解析函数
    IPv6ExtensionHeader parseIPv6ExtensionHeader(const unsigned char *packetData);
    void parseIPv4Packet(PacketInfo &packetInfo, const unsigned char *packetData);
    void parseIPv6Packet(PacketInfo &packetInfo, const unsigned char *packetData, int &offset, ProtocolNode &ipv6Node);
    void parseARPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    void parseRIPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    RouteEntry parseRouteEntry(const unsigned char *packetData);
    void parseICMPPacket(PacketInfo &packetInfo, const unsigned char *packetData); // 解析ICMP数据包
    void parseIGMPPacket(PacketInfo &packetInfo, const unsigned char *packetData); // 解析IGMP数据包
    TCPHeader parseTCPHeader(const unsigned char *packetData);
    void parseTCPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    UDPHeader parseUDPHeader(const unsigned char *packetData);
    void parseUDPPacket(PacketInfo &packetInfo, const unsigned char *packetData);
    DNSHeader parseDNSHeader(const unsigned char *packetData);
    bool isHTTPPayload(const unsigned char *payload, int length);
    void parseHTTP(PacketInfo &packetInfo, const unsigned char *payload, int payloadSize);
    void parseDNSPacket(PacketInfo &packetInfo, const unsigned char *packetData);
};

#endif // PARSER_H
