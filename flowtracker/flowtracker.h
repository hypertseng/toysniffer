#ifndef FLOWTRACKER_H
#define FLOWTRACKER_H

#include "parser.h"
#include <unordered_map>
#include <tuple>

struct FlowKey
{
    std::string srcIP;
    std::string destIP;
    std::string protocol;

    bool operator==(const FlowKey &other) const
    {
        return std::tie(srcIP, destIP, protocol) == std::tie(other.srcIP, other.destIP, other.protocol);
    }
};

// 自定义哈希函数
struct FlowKeyHash
{
    std::size_t operator()(const FlowKey &key) const
    {
        return std::hash<std::string>()(key.srcIP) ^
               (std::hash<std::string>()(key.destIP) << 1) ^
               (std::hash<std::string>()(key.protocol) << 2);
    }
};

struct FlowInfo
{
    int packetCount;
    int byteCount;
};

class FlowTracker
{
public:
    void updateFlow(const ParsedPacket &pkt);
    std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> getFlows() const;

private:
    std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> flows;
};

#endif // FLOWTRACKER_H