#ifndef PACKETMODEL_H
#define PACKETMODEL_H

#include <QAbstractTableModel>
#include "parser.h"
#include <vector>

class PacketTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    PacketTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void addPacket(const ParsedPacket &pkt);

private:
    std::vector<ParsedPacket> packets;
};

#endif // PACKETMODEL_H