#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <string>
#include "capture.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// 定义解析后的数据包结构
struct ParsedPacket
{
    std::string timestamp;
    std::string srcIP;
    std::string destIP;
    std::string protocol;
    int length;
    // 可扩展更多字段
};

struct TCPHeader
{
    u_short srcPort;
    u_short destPort;
    uint32_t sequence;
    uint32_t acknowledgment;
    u_char dataOffset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgentPointer;
};

// 数据包解析类
class PacketParser
{
public:
    ParsedPacket parse(const RawPacket &rawPkt);
};

#endif // PARSER_H

