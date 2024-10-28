#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "capture.h"
#include "parser.h"

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
    void onHandleFilterChange();
    void onPacketSelected(const QModelIndex &index);

private:
    Ui::MainWindow *ui;
    char errbuf[PCAP_ERRBUF_SIZE]; /* error string */
    pcap_if_t *alldevs;
    QTimer *filterTimer;
    QStandardItemModel *packetInfoModel; // 使用 QStandardItemModel 作为数据模型
    ProtocolParser *protocolpaser;
    PacketCapture *capture;
    std::vector<ProtocolNode> allProtocolNode;
    std::vector<DataNode> allDataNode;
    std::pair<QString, QString> formatRawData(const u_char *data, int length);

    // void setupTableView();  // 设置 QTableView 的函数
    // void updatePacketList(const ProtocolParser& protocolpaser);  // 更新数据表格函数
    void loadPacketData(const PacketInfo &packetInfo); // 加载捕获的数据包并展示在表格中
    // void updatePacketDetails(const std::vector<unsigned char>& packet); // 更新详情和二进制表示
    void packetCallback(const RawPacket &pkt);
};

#endif // MAINWINDOW_H
