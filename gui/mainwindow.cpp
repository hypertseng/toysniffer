#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "flowtracker.h"
#include "flowmodel.h"
// 在 MainWindow 类中添加成员
FlowTracker *flowTracker;

// 在 MainWindow 类中添加成员
FlowTableModel *flowModel;

// 在构造函数中初始化
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), packetCapture(new PacketCapture()), packetParser(new PacketParser()), tableModel(new PacketTableModel()), flowTracker(new FlowTracker()), flowModel(new FlowTableModel())
{
    ui->setupUi(this);

    // 设置数据包列表视图
    ui->packetTableView->setModel(tableModel);

    // 设置流信息视图
    ui->flowTableView->setModel(flowModel);

    // 连接捕获回调
    packetCapture->onPacketCaptured = [this](const RawPacket &pkt)
    {
        handleCapturedPacket(pkt);
    };

    // 填充网络接口
    populateInterfaces();

    connect(ui->startButton, &QPushButton::clicked, this, &MainWindow::on_startButton_clicked);
    connect(ui->stopButton, &QPushButton::clicked, this, &MainWindow::on_stopButton_clicked);
}

// 修改 handleCapturedPacket 函数
void MainWindow::handleCapturedPacket(const RawPacket &rawPkt)
{
    ParsedPacket parsed = packetParser->parse(rawPkt);
    flowTracker->updateFlow(parsed);

    // 更新 GUI 必须在主线程中进行
    QMetaObject::invokeMethod(this, [this, parsed]()
                              {
        tableModel->addPacket(parsed);
        flowModel->updateFlows(flowTracker->getFlows()); }, Qt::QueuedConnection);

    // 释放内存
    delete rawPkt.header;
    delete[] rawPkt.data;
}

// 在析构函数中删除
MainWindow::~MainWindow()
{
    packetCapture->stopCapture();
    delete ui;
    delete flowTracker;
    delete flowModel;
}
