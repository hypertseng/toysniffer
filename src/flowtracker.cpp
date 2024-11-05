#include <string>
#include <sstream>
#include <vector>
#include <cstdio>
#include <memory>
#include "flowtracker.h"

void FlowTracker::trackPacket(const PacketInfo &packetInfo)
{
    FlowKey key = {packetInfo.sourceIP, packetInfo.destinationIP,
                   packetInfo.sourcePort, packetInfo.destinationPort};

    auto &flowData = flows[key];
    flowData.push_back({packetInfo.time, packetInfo.length});
}

const std::unordered_map<FlowKey, std::vector<std::pair<std::string, int>>> &FlowTracker::getFlows() const
{
    return flows;
}

bool FlowTracker::processTrackPacket(const PacketInfo &packetInfo, const std::string &processID)
{
    if (isPacketFromProcess(packetInfo, processID))
    {
        trackPacket(packetInfo);
        return true;
    }
    return false;
}

std::vector<std::string> FlowTracker::executeCommand(const std::string &command)
{
    std::vector<std::string> result;
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result.emplace_back(buffer.data());
    }

    return result;
}

bool FlowTracker::isPacketFromProcess(const PacketInfo &packetInfo, const std::string &processID)
{
    std::string command = "lsof -i -n -P | grep " + processID;
    std::vector<std::string> output = executeCommand(command);

    for (const auto &line : output)
    {
        std::istringstream iss(line);
        std::string processName, pid, user, fd, type, device, size_off, node, name;

        // 提取 PID 和进程名称
        iss >> processName >> pid >> user >> fd >> type >> device >> size_off >> node;

        // 检查 PID 是否匹配
        if (pid != processID)
            continue;

        // 检查连接信息是否匹配
        if (iss >> name)
        { // 获取连接信息
            // 提取 IP:port 信息
            std::string ipPortInfo = name.substr(name.find_first_of(" ") + 1); // 提取 IP:port 信息
            std::string ip = ipPortInfo.substr(0, ipPortInfo.find(':'));
            std::string port = ipPortInfo.substr(ipPortInfo.find(':') + 1, ipPortInfo.find('(') - ipPortInfo.find(':') - 1); // 提取端口

            // 检查 IP 和端口的匹配逻辑
            bool ipMatches = (ip == packetInfo.sourceIP || ip == "*");
            bool portMatches = (port == std::to_string(packetInfo.sourcePort) || port == "*");

            if (ipMatches && portMatches)
            {
                return true;
            }
        }
    }
    return false;
}
