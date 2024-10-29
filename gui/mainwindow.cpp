#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDateTime>
#include <QTimer>
#include <QDir>
#include <QProcess>
#include <QRegularExpression>
#include <QChartView>
#include <QValueAxis>
#include <QLineSeries>
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

    // 将微秒部分添加到时间字符串中，并只保留三位小数
    std::stringstream ss;
    ss << buffer << "." << std::setw(3) << std::setfill('0') << (tv.tv_usec / 1000); // 将微秒转换为毫秒
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
    if (ui->filterComboBox->currentText().toStdString() != "不过滤协议..." && ui->filterComboBox->currentText().toStdString() != packetInfo.protocol)
        return;

    packetInfo.time = convertTimevalToString(pkt.ts);
    if (ui->processComboBox->currentText() != "未选择任何进程...")
    {
        bool isProcessPacket;
        isProcessPacket = flowTracker.processTrackPacket(packetInfo, selectedProcessID.toStdString());
        if (isProcessPacket)
        {
            loadPacketData(packetInfo);
            totalLength += packetInfo.length;
        }
    }
    else
    {
        loadPacketData(packetInfo);
    }
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
      timer(new QTimer(this)),
      packetInfoModel(new QStandardItemModel(this)),
      protocolpaser(new ProtocolParser()),
      capture(new PacketCapture()),
      totalLength(0)
{
    ui->setupUi(this);

    // 设置窗口标题
    setWindowTitle("toysniffer");

    // 设置窗口大小
    setGeometry(0, 0, 800, 600);

    // 设置定时器的超时时间
    timer = new QTimer;
    timer->setInterval(1000); // 1秒后触发
    timer->start();

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

    ui->filterComboBox->addItem("不过滤协议...", Protocol::OTHER);
    ui->filterComboBox->addItem("TCP", Protocol::TCP);
    ui->filterComboBox->addItem("UDP", Protocol::UDP);
    ui->filterComboBox->addItem("ICMP", Protocol::ICMP);
    ui->filterComboBox->addItem("HTTP", Protocol::HTTP);
    ui->filterComboBox->addItem("HTTPS", Protocol::HTTPS);
    ui->filterComboBox->addItem("DNS", Protocol::DNS);
    ui->filterComboBox->addItem("ARP", Protocol::ARP);
    ui->filterComboBox->addItem("RIP", Protocol::RIP);
    ui->filterComboBox->addItem("IGMP", Protocol::IGMP);

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

    // 初始化图表
    auto axisX = new QValueAxis();
    auto axisY = new QValueAxis();
    QFont fontX, fontY, legendFont;
    fontX.setPointSize(6);
    fontY.setPointSize(10);
    ui->chartView->chart()->legend()->setFont(legendFont);
    ui->chartView->chart()->legend()->setMarkerShape(QLegend::MarkerShapeFromSeries);
    ui->chartView->chart()->setMargins(QMargins(0, 0, 0, 0));
    axisY->setLabelsFont(fontY);
    axisX->setLabelsAngle(45);
    axisX->setTitleText("时间 (s)");
    axisY->setTitleText("报文长度 (bytes)");
    axisY->setMax(65535);
    // 隐藏刻度标签和刻度线
    axisX->setLabelsVisible(false);  // 隐藏刻度标签
    axisX->setLineVisible(false);    // 隐藏轴的刻度线
    axisY->setTickCount(4);  // 设置Y轴刻度数量

    auto lineSeries = new QLineSeries();                             // 创建曲线绘制对象
    lineSeries->setPointsVisible(true);                         // 设置数据点可见
    lineSeries->setName("网络数据流曲线");                            // 图例名称
    QChart *chart = new QChart();                                    // 创建图表对象
    chart->addAxis(axisX, Qt::AlignBottom);                      // 将X轴添加到图表上
    chart->addAxis(axisY, Qt::AlignLeft);                    // 将Y轴添加到图表上
    chart->addSeries(lineSeries);                              // 将曲线对象添加到图表上
    chart->setAnimationOptions(QChart::SeriesAnimations);        // 动画：能使曲线绘制显示的更平滑，过渡效果更好看

    lineSeries->attachAxis(axisX);                             // 曲线对象关联上X轴，此步骤必须在m_chart->addSeries之后
    lineSeries->attachAxis(axisY);                             // 曲线对象关联上Y轴，此步骤必须在m_chart->addSeries之后

    ui->chartView->setChart(chart);                           // 将图表对象设置到graphicsView上进行显示
    ui->chartView->setRenderHint(QPainter::Antialiasing);       // 设置渲染：抗锯齿，如果不设置那么曲线就显得不平滑

    initializeProcessComboBox();

    // 信号与槽的连接
    connect(ui->startCaptureButton, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->stopCaptureButton, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->interfaceComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onComboBoxChanged);
    connect(ui->filterComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::onFilterChanged);
    // 当用户点击表格中的某一行时，调用槽函数 onPacketSelected
    connect(ui->packetTableView, &QTableView::clicked, this, &MainWindow::onPacketSelected);
    connect(ui->processComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onProcessSelected);
    // connect(timer, &QTimer::timeout, this, &MainWindow::initializeProcessComboBox);
    connect(timer, &QTimer::timeout, this, &MainWindow::updateWaveform);
}

MainWindow::~MainWindow()
{
    delete ui;
    allProtocolNode.clear();
}

void MainWindow::onComboBoxChanged()
{
    ui->logTextEdit->append(get_time() + "\n已选择网络端口" + ui->interfaceComboBox->currentText());
    allProtocolNode.clear();
    ui->packetTableView->model()->removeRows(0, ui->packetTableView->model()->rowCount());
}

void MainWindow::onFilterChanged()
{
    allProtocolNode.clear();
    ui->packetTableView->model()->removeRows(0, ui->packetTableView->model()->rowCount());
}

// 开始抓包的槽函数
void MainWindow::onStartCapture()
{
    // 处理开始抓包的逻辑
    ui->logTextEdit->append(get_time() + "\n开始嗅探...");
    std::string filterExp;
    Protocol protocolType = static_cast<Protocol>(ui->filterComboBox->currentData().toInt());
    // 根据协议字符串生成过滤表达式
    switch (protocolType)
    {
    case Protocol::TCP:
        filterExp = "tcp";
        break;
    case Protocol::UDP:
        filterExp = "udp";
        break;
    case Protocol::ICMP:
        filterExp = "icmp";
        break;
    case Protocol::HTTP:
        filterExp = "tcp port 80";
        break;
    case Protocol::HTTPS:
        filterExp = "tcp port 443";
        break;
    case Protocol::DNS:
        filterExp = "udp port 53";
        break;
    case Protocol::ARP:
        filterExp = "arp";
        break;
    case Protocol::RIP:
        filterExp = "udp port 520";
        break;
    case Protocol::IGMP:
        filterExp = "igmp";
        break;
    default:
        filterExp = ""; // 不设置过滤器，捕获所有数据包
        break;
    }

    if (!capture->startCapture(ui->interfaceComboBox->currentText().toStdString(), filterExp))
    {

        ui->logTextEdit->append(get_time() + "\n无法开始捕获数据包");
    }
    ui->logTextEdit->append(get_time() + "\n正在捕获数据包，点击停止，结束嗅探...");
}

// 停止抓包的槽函数
void MainWindow::onStopCapture()
{
    ui->logTextEdit->append(get_time() + "\n停止嗅探...");
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

void MainWindow::onProcessSelected(int index)
{
    allProtocolNode.clear();
    ui->logTextEdit->append(get_time() + "\n已选择进程" + ui->processComboBox->currentText());
    ui->filterComboBox->setCurrentIndex(1);
    // 获取选中的进程 ID，进行数据过滤和波形更新
    QString processID = ui->processComboBox->itemData(index).toString();
    selectedProcessID = processID; // 存储选定的进程 ID
}

void MainWindow::updateWaveform()
{
    QLineSeries *lineSeries = qobject_cast<QLineSeries *>(ui->chartView->chart()->series().first());
    if (!lineSeries) {
        return; // 确保 lineSeries 不为空
    }

    // 使用当前时间作为横坐标
    double currentTime = QDateTime::currentDateTime().toMSecsSinceEpoch() / 1000.0; // 转换为秒

    // 打印 totalLength 值进行调试
    qDebug() << "Total Length:" << totalLength;

    // 添加新点
    lineSeries->append(currentTime, static_cast<int>(totalLength));

    // 维护最多30个数据点
    while (lineSeries->points().size() > 30) {
        lineSeries->remove(0); // 移除最旧的点
    }

    // 更新X轴范围
    QList<QAbstractAxis *> xAxes = ui->chartView->chart()->axes(Qt::Horizontal);
    if (!xAxes.isEmpty()) {
        QAbstractAxis *xAxis = xAxes.first();
        xAxis->setMax(currentTime); // 更新X轴最大值为当前时间
        xAxis->setMin(currentTime - 30); // 更新X轴最小值为当前时间前30秒
    }

    // 更新图表视图
    ui->chartView->update();

    totalLength = 0;
}

void MainWindow::initializeProcessComboBox()
{
    ui->processComboBox->clear();
    ui->processComboBox->addItem("未选择任何进程...");

    // 使用 lsof 命令列出所有使用网络的进程
    QProcess process;
    process.start("lsof", QStringList() << "-i" << "-n" << "-P");

    if (!process.waitForFinished())
    {
        qDebug() << "Process failed to finish:" << process.errorString();
        return;
    }

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);

    static const QRegularExpression whitespaceRegex("\\s+");

    // 使用 QMap 来存储已处理的进程信息
    QMap<QString, QStringList> processMap;

    // 跳过标题行并处理每一行
    for (int i = 1; i < lines.size(); ++i)
    {
        QString line = lines[i].simplified();
        QStringList parts = line.split(whitespaceRegex);

        if (parts.size() >= 9) // 确保行格式正确
        {
            QString processName = parts[0]; // 进程名称
            QString pid = parts[1]; // PID
            QString user = parts[2]; // 用户名
            QString connectionInfo = parts[8]; // NAME (网络连接信息)

            // 提取 IP:port 信息
            QStringList connectionParts = connectionInfo.split(":");
            if (connectionParts.size() == 2)
            {
                QString ip = connectionParts[0]; // IP
                QString port = connectionParts[1]; // port
                QString displayText = ip + ":" + port; // 格式化后的 IP:port 信息
                QString itemText = user + " - " + processName + " (PID: " + pid + ") - " + displayText;
                ui->processComboBox->addItem(itemText, pid);
            }
        }
    }
}
