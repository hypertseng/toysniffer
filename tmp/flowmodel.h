#ifndef FLOWMODEL_H
#define FLOWMODEL_H

#include <QAbstractTableModel>
#include "flowtracker.h"
#include <vector>

struct DisplayFlow
{
    QString srcIP;
    QString destIP;
    QString protocol;
    int packetCount;
    int byteCount;
};

class FlowTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    FlowTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void updateFlows(const std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> &flows);

private:
    std::vector<DisplayFlow> displayFlows;
};

#endif // FLOWMODEL_H