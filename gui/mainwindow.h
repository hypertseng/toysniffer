#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "capture.h"
#include "flowtracker.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onComboBoxChanged();
    void onFilterChanged();
    void onPacketSelected(const QModelIndex &index);
    void updateWaveform();
    void onProcessSelected(int index);

private:
    Ui::MainWindow *ui;
    char errbuf[PCAP_ERRBUF_SIZE]; /* error string */
    pcap_if_t *alldevs;
    QTimer *timer;
    QStandardItemModel *packetInfoModel; // 使用 QStandardItemModel 作为数据模型
    ProtocolParser *protocolpaser;
    PacketCapture *capture;
    std::vector<ProtocolNode> allProtocolNode;
    std::vector<DataNode> allDataNode;
    std::pair<QString, QString> formatRawData(const u_char *data, int length);
    FlowTracker flowTracker;
    QString selectedProcessID;
    long totalLength;
    void loadPacketData(const PacketInfo &packetInfo); // 加载捕获的数据包并展示在表格中
    void packetCallback(const RawPacket &pkt);
    void initializeProcessComboBox();
};

#endif // MAINWINDOW_H
