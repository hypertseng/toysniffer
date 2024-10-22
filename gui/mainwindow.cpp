#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "parse.h"
#include "QDateTime"
#include "QTimer"

// 获取当前时间
QString get_time()
{
    return QDateTime::currentDateTime().toString("[yyyy-MM-dd HH:mm:ss]\t");
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 设置窗口标题
    setWindowTitle("toysniffer");

    // 设置窗口大小
    setGeometry(0, 0, 800, 600);

    // 设置定时器的超时时间
    filterTimer = new QTimer;
    filterTimer->setInterval(2000); // 2秒后触发

    // 信号与槽的连接
    connect(ui->startCaptureButton, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->stopCaptureButton, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->interfaceComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onComboBoxChanged);
    connect(ui->filterLineEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    connect(filterTimer, &QTimer::timeout, this, &MainWindow::handleFilterChange);

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
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::onComboBoxChanged()
{
    ui->logTextEdit->append(get_time() + "已选择网络端口" + ui->interfaceComboBox->currentText());
}

void MainWindow::handleFilterChange()
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
}

// 开始抓包的槽函数
void MainWindow::onStartCapture()
{
    // 处理开始抓包的逻辑
    ui->logTextEdit->append(get_time() + "开始嗅探...");

}

// 停止抓包的槽函数
void MainWindow::onStopCapture()
{
    ui->logTextEdit->append(get_time() + "停止嗅探...");
}


