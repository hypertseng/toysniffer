#include "flowtracker.h"

void FlowTracker::updateFlow(const ParsedPacket &pkt)
{
    FlowKey key = {pkt.srcIP, pkt.destIP, pkt.protocol};
    auto it = flows.find(key);
    if (it != flows.end())
    {
        it->second.packetCount += 1;
        it->second.byteCount += pkt.length;
    }
    else
    {
        flows[key] = FlowInfo{1, pkt.length};
    }
}

std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> FlowTracker::getFlows() const
{
    return flows;
}