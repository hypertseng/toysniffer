#include "flowmodel.h"

FlowTableModel::FlowTableModel(QObject *parent)
    : QAbstractTableModel(parent) {}

int FlowTableModel::rowCount(const QModelIndex &parent) const
{
    return displayFlows.size();
}

int FlowTableModel::columnCount(const QModelIndex &parent) const
{
    return 5; // 源IP、目的IP、协议、包数、字节数
}

QVariant FlowTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || role != Qt::DisplayRole)
        return QVariant();

    const DisplayFlow &flow = displayFlows[index.row()];
    switch (index.column())
    {
    case 0:
        return flow.srcIP;
    case 1:
        return flow.destIP;
    case 2:
        return flow.protocol;
    case 3:
        return flow.packetCount;
    case 4:
        return flow.byteCount;
    default:
        return QVariant();
    }
}

QVariant FlowTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
    {
        switch (section)
        {
        case 0:
            return "源IP";
        case 1:
            return "目的IP";
        case 2:
            return "协议";
        case 3:
            return "包数";
        case 4:
            return "字节数";
        default:
            return QVariant();
        }
    }
    return QVariant();
}

void FlowTableModel::updateFlows(const std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> &flows)
{
    beginResetModel();
    displayFlows.clear();
    for (const auto &[key, info] : flows)
    {
        DisplayFlow flow;
        flow.srcIP = QString::fromStdString(key.srcIP);
        flow.destIP = QString::fromStdString(key.destIP);
        flow.protocol = QString::fromStdString(key.protocol);
        flow.packetCount = info.packetCount;
        flow.byteCount = info.byteCount;
        displayFlows.push_back(flow);
    }
    endResetModel();
}