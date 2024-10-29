#include <unordered_map>
#include <vector>
#include "parser.h"

struct FlowKey
{
    std::string sourceIP;
    std::string destinationIP;
    int sourcePort;
    int destinationPort;

    // 用于哈希表的相等判断
    bool operator==(const FlowKey &other) const
    {
        return sourceIP == other.sourceIP &&
               destinationIP == other.destinationIP &&
               sourcePort == other.sourcePort &&
               destinationPort == other.destinationPort;
    }
};

// 自定义哈希函数
namespace std
{
    template <>
    struct hash<FlowKey>
    {
        size_t operator()(const FlowKey &key) const
        {
            return hash<string>()(key.sourceIP) ^ hash<string>()(key.destinationIP) ^
                   hash<int>()(key.sourcePort) ^ hash<int>()(key.destinationPort);
        }
    };
}

class FlowTracker
{
public:
    const std::unordered_map<FlowKey, std::vector<std::pair<std::string, int>>> &getFlows() const;
    bool isPacketFromProcess(const PacketInfo &packetInfo, const std::string &processID);
    bool processTrackPacket(const PacketInfo &packetInfo, const std::string &processID);

private:
    void trackPacket(const PacketInfo &packetInfo);
    std::unordered_map<FlowKey, std::vector<std::pair<std::string, int>>> flows;
    std::vector<std::string> executeCommand(const std::string& command);
};
