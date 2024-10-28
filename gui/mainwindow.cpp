#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QDateTime"
#include "QTimer"
#include <iomanip>

// 获取当前时间
QString get_time()
{
    return QDateTime::currentDateTime().toString("[yyyy-MM-dd HH:mm:ss]\t");
}

std::string convertTimevalToString(const timeval &tv)
{
    // 将秒数转换为本地时间
    struct tm *tm_info = localtime(&tv.tv_sec);
    char buffer[64];
    // 格式化日期和时间为 "YYYY-MM-DD HH:MM:SS"
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    // 将微秒部分添加到时间字符串中
    std::stringstream ss;
    ss << buffer << "." << std::setw(6) << std::setfill('0') << tv.tv_usec; // 格式化微秒部分为6位
    return ss.str();
}

void addNodeToModel(QStandardItem *parentItem, const ProtocolNode &node)
{
    QStandardItem *item = new QStandardItem(QString::fromStdString(node.protocolName + ": " + node.details));
    parentItem->appendRow(item);

    // 递归添加子节点
    for (const auto &child : node.children)
    {
        addNodeToModel(item, child);
    }
}

void populateProtocolTreeView(QTreeView *treeView, const ProtocolNode &rootNode)
{
    QStandardItemModel *model = new QStandardItemModel;
    QStandardItem *rootItem = model->invisibleRootItem();

    // 添加根节点的子节点
    addNodeToModel(rootItem, rootNode);

    treeView->setModel(model);
}

std::pair<QString, QString> MainWindow::formatRawData(const u_char *data, int length)
{
    std::stringstream hexStream, asciiStream;

    for (int i = 0; i < length; i += 16)
    {
        hexStream << std::setw(4) << std::setfill('0') << std::hex << i << "  "; // 行偏移地址
        for (int j = 0; j < 16; ++j)
        {
            if (i + j < length)
                hexStream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i + j]) << " "; // 十六进制值
            else
                hexStream << "   "; // 空格填充
        }
        hexStream << " "; // 十六进制和 ASCII 之间的分隔

        for (int j = 0; j < 16; ++j)
        {
            if (i + j < length)
            {
                char ch = static_cast<char>(data[i + j]);
                asciiStream << (std::isprint(ch) ? ch : '.'); // 显示可打印字符，非可打印字符用 '.'
            }
            else
            {
                asciiStream << ' '; // 空格填充
            }
        }
        hexStream << "\n";   // 换行
        asciiStream << "\n"; // 换行
    }

    return {QString::fromStdString(hexStream.str()), QString::fromStdString(asciiStream.str())};
}

// libpcap 的回调函数
void MainWindow::packetCallback(const RawPacket &pkt)
{
    PacketInfo packetInfo;
    ProtocolNode protocolNode;

    // 从 RawPacket 中提取数据和长度
    const unsigned char *packetDataPtr = pkt.data.get(); // 获取数据包数据指针
    int length = pkt.header->len;                        // 获取数据包长度
    protocolNode.protocolName = "RawPacket";
    protocolNode.details = "Length: " + std::to_string(length) + " bytes";

    // 解析数据包
    protocolpaser->parsePacketLayers(packetInfo, packetDataPtr, length, protocolNode);
    // 过滤掉不符合所选择协议的数据报，如来自tcp 80端口的非HTTP数据报
    if (ui->filterLineEdit->text().toStdString() != "" && ui->filterLineEdit->text().toStdString() != packetInfo.protocol)
        return;
    packetInfo.time = convertTimevalToString(pkt.ts);
    loadPacketData(packetInfo);
    allProtocolNode.push_back(protocolNode);
    allDataNode.push_back({length, packetDataPtr});
}

void MainWindow::loadPacketData(const PacketInfo &packetInfo)
{
    // 创建一行数据，包含时间、源地址、目的地址、协议和信息
    QList<QStandardItem *> rowData;

    // 创建新的 QStandardItem 对象并设置文本
    rowData.append(new QStandardItem(QString::fromStdString(packetInfo.time)));                   // 时间
    rowData.append(new QStandardItem(QString::fromStdString(packetInfo.sourceIP)));               // 源地址
    rowData.append(new QStandardItem(QString::fromStdString(packetInfo.destinationIP)));          // 目的地址
    rowData.append(new QStandardItem(QString::fromStdString(packetInfo.protocol)));               // 协议
    rowData.append(new QStandardItem(QString::fromStdString(std::to_string(packetInfo.length)))); // 报文长度
    rowData.append(new QStandardItem(QString::fromStdString(packetInfo.info)));                   // 信息

    // 将新行添加到模型中
    packetInfoModel->appendRow(rowData);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      filterTimer(new QTimer(this)),
      packetInfoModel(new QStandardItemModel(this)),
      protocolpaser(new ProtocolParser()),
      capture(new PacketCapture())
{
    ui->setupUi(this);

    // 设置窗口标题
    setWindowTitle("toysniffer");

    // 设置窗口大小
    setGeometry(0, 0, 800, 600);

    // 设置定时器的超时时间
    filterTimer = new QTimer;
    filterTimer->setInterval(2000); // 2秒后触发

    // 设置本机网络端口
    pcap_findalldevs(&alldevs, errbuf);
    pcap_if_t *dev = nullptr;
    // 添加可选值
    QStringList options;
    for (dev = alldevs; dev != nullptr; dev = dev->next)
    {
        QString devstr = dev->name;
        if (dev->description)
        {
            devstr += "(" + QString(dev->description) + ")";
        }
        options.append(devstr);
    }
    options.sort(Qt::CaseInsensitive);
    ui->interfaceComboBox->addItems(options);

    // 设置 QLineEdit 的占位符文本
    ui->filterLineEdit->setPlaceholderText("请输入协议类型...");

    QStringList headList; // 表头
    headList << QString::fromLocal8Bit("Time") << QString::fromLocal8Bit("Source")
             << QString::fromLocal8Bit("Destination") << QString::fromLocal8Bit("Protocol")
             << QString::fromLocal8Bit("Length") << QString::fromLocal8Bit("Info");
    packetInfoModel->setHorizontalHeaderLabels(headList);
    ui->packetTableView->setModel(packetInfoModel);
    ui->packetTableView->horizontalHeader()->setVisible(true);
    ui->packetTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->packetTableView->horizontalHeader()->setStretchLastSection(true);

    capture->callback = std::bind(&MainWindow::packetCallback, this, std::placeholders::_1);

    // ui->rawDataLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);  // 左上对齐
    ui->rawDataHexLabel->setText("Capturing packets...");

    // 信号与槽的连接
    connect(ui->startCaptureButton, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->stopCaptureButton, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->interfaceComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onComboBoxChanged);
    connect(ui->filterLineEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    connect(filterTimer, &QTimer::timeout, this, &MainWindow::onHandleFilterChange);
    // 当用户点击表格中的某一行时，调用槽函数 onPacketSelected
    connect(ui->packetTableView, &QTableView::clicked, this, &MainWindow::onPacketSelected);
}

MainWindow::~MainWindow()
{
    delete ui;
    allProtocolNode.clear();
}

void MainWindow::onComboBoxChanged()
{
    ui->logTextEdit->append(get_time() + "已选择网络端口" + ui->interfaceComboBox->currentText());
    allProtocolNode.clear();
    ui->packetTableView->model()->removeRows(0, ui->packetTableView->model()->rowCount());
}

void MainWindow::onHandleFilterChange()
{
    // 停止定时器，处理过滤逻辑
    filterTimer->stop();

    if (supportedProtocols.find(ui->filterLineEdit->text().toStdString()) != supportedProtocols.end())
    {
        ui->logTextEdit->append(get_time() + "已选择协议类型" + ui->filterLineEdit->text());
    }
    else
    {
        ui->logTextEdit->append(get_time() + "请输入有效协议类型！");
    }
}

void MainWindow::onFilterChanged()
{
    filterTimer->start();
    allProtocolNode.clear();
    ui->packetTableView->model()->removeRows(0, ui->packetTableView->model()->rowCount());
}

// 开始抓包的槽函数
void MainWindow::onStartCapture()
{
    // 处理开始抓包的逻辑
    ui->logTextEdit->append(get_time() + "开始嗅探...");
    std::string filterExp;
    std::string protocolType = ui->filterLineEdit->text().toStdString();
    // 根据协议字符串生成过滤表达式
    if (protocolType == "TCP" || protocolType == "tcp")
        filterExp = "tcp";
    else if (protocolType == "UDP" || protocolType == "udp")
        filterExp = "udp";
    else if (protocolType == "ICMP" || protocolType == "icmp")
        filterExp = "icmp";
    else if (protocolType == "HTTP" || protocolType == "http")
        filterExp = "tcp port 80";
    else if (protocolType == "HTTPS" || protocolType == "https")
        filterExp = "tcp port 443";
    else if (protocolType == "FTP" || protocolType == "ftp")
        filterExp = "tcp port 21";
    else if (protocolType == "DNS" || protocolType == "dns")
        filterExp = "udp port 53";
    else if (protocolType == "ARP" || protocolType == "arp")
        filterExp = "arp";
    else if (protocolType == "RIP" || protocolType == "rip")
        filterExp = "udp port 520";
    else if (protocolType == "IGMP" || protocolType == "igmp")
        filterExp = "igmp";
    else
        filterExp = ""; // 不设置过滤器，捕获所有数据包

    if (!capture->startCapture(ui->interfaceComboBox->currentText().toStdString(), filterExp))
    {

        ui->logTextEdit->append(get_time() + "无法开始捕获数据包");
    }
    ui->logTextEdit->append(get_time() + "正在捕获数据包，点击停止，结束嗅探...");
}

// 停止抓包的槽函数
void MainWindow::onStopCapture()
{
    ui->logTextEdit->append(get_time() + "停止嗅探...");
    capture->stopCapture();
}

void MainWindow::onPacketSelected(const QModelIndex &index)
{
    // 检查索引是否有效
    if (!index.isValid())
    {
        return; // 如果无效，直接返回
    }
    // 获取所选行和列
    int row = index.row();
    ProtocolNode node = allProtocolNode[row];
    populateProtocolTreeView(ui->protocolTreeView, node);

    auto [hexText, asciiText] = formatRawData(allDataNode[row].data, allDataNode[row].length);
    ui->rawDataHexLabel->setText(hexText); // 将格式化内容设置为QLabel文本
    ui->rawDataAsciiLabel->setText(asciiText);
}
