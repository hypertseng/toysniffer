#include "parse.h"
#include <arpa/inet.h>
#include <ctime>
#include <sstream>
#include <netinet/tcp.h>

ParsedPacket PacketParser::parse(const RawPacket &rawPkt)
{
    ParsedPacket pkt;

    // 时间戳
    std::time_t t = rawPkt.header->ts.tv_sec;
    std::tm *tm_info = std::localtime(&t);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    pkt.timestamp = std::string(buffer);

    // 以太网头部偏移
    const int ethernetHeaderLength = 14;
    if (rawPkt.header->caplen < ethernetHeaderLength)
    {
        // 数据包太短，无法解析
        return pkt;
    }

    // IP头部
    const struct ip *ipHeader = (struct ip *)(rawPkt.data + ethernetHeaderLength);
    pkt.srcIP = std::string(inet_ntoa(ipHeader->ip_src));
    pkt.destIP = std::string(inet_ntoa(ipHeader->ip_dst));
    pkt.length = ntohs(ipHeader->ip_len);

    // 协议
    switch (ipHeader->ip_p)
    {
    case IPPROTO_TCP:
        pkt.protocol = "TCP";
        break;
    case IPPROTO_UDP:
        pkt.protocol = "UDP";
        break;
    case IPPROTO_ICMP:
        pkt.protocol = "ICMP";
        break;
    default:
        pkt.protocol = "OTHER";
        break;
    }

    // 在解析 IP 协议后
    if (ipHeader->ip_p == IPPROTO_TCP)
    {
        const struct tcphdr *tcpHeader = (struct tcphdr *)(rawPkt.data + ethernetHeaderLength + ipHeader->ip_hl * 4);
        // 提取 TCP 相关信息
        // 例如，源端口和目的端口
        pkt.srcIP += ":" + std::to_string(ntohs(tcpHeader->th_sport));
        pkt.destIP += ":" + std::to_string(ntohs(tcpHeader->th_dport));
        // 可以添加更多字段
    }

    return pkt;
}