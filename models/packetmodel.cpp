#include "packetmodel.h"

PacketTableModel::PacketTableModel(QObject *parent)
    : QAbstractTableModel(parent) {}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    return packets.size();
}

int PacketTableModel::columnCount(const QModelIndex &parent) const
{
    return 5; // 时间、源IP、目的IP、协议、长度
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || role != Qt::DisplayRole)
        return QVariant();

    const ParsedPacket &pkt = packets[index.row()];
    switch (index.column())
    {
    case 0:
        return QString::fromStdString(pkt.timestamp);
    case 1:
        return QString::fromStdString(pkt.srcIP);
    case 2:
        return QString::fromStdString(pkt.destIP);
    case 3:
        return QString::fromStdString(pkt.protocol);
    case 4:
        return pkt.length;
    default:
        return QVariant();
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
    {
        switch (section)
        {
        case 0:
            return "时间";
        case 1:
            return "源IP";
        case 2:
            return "目的IP";
        case 3:
            return "协议";
        case 4:
            return "长度";
        default:
            return QVariant();
        }
    }
    return QVariant();
}

void PacketTableModel::addPacket(const ParsedPacket &pkt)
{
    beginInsertRows(QModelIndex(), packets.size(), packets.size());
    packets.push_back(pkt);
    endInsertRows();
}