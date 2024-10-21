#include <QApplication>
#include <QMainWindow>
#include <QComboBox>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QThread>
#include <iostream>
#include <pcap.h>
#include <string>

class PacketCapture : public QObject
{
    Q_OBJECT

public:
    PacketCapture(const std::string &device, const std::string &filter) : target_device(device), filter_expr(filter)
    {
        // 初始化捕获设备
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_lookupnet(target_device.c_str(), &net, &mask, errbuf);
        handle = pcap_open_live(target_device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle)
        {
            std::cerr << "无法打开设备 " << target_device << ": " << errbuf << std::endl;
            exit(1);
        }

        // 编译过滤器
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1)
        {
            std::cerr << "无法编译过滤器: " << pcap_geterr(handle) << std::endl;
            exit(1);
        }
        if (pcap_setfilter(handle, &fp) == -1)
        {
            std::cerr << "无法设置过滤器: " << pcap_geterr(handle) << std::endl;
            exit(1);
        }
    }

    ~PacketCapture()
    {
        pcap_close(handle);
    }

public slots:
    void startCapture()
    {
        capturing = true;
        while (capturing)
        {
            pcap_dispatch(handle, 1, &PacketCapture::packetHandler, reinterpret_cast<u_char *>(this));
        }
    }

    void stopCapture()
    {
        capturing = false;
    }

private:
    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
    {
        auto *instance = reinterpret_cast<PacketCapture *>(args);
        QString output = QString("捕获到一个数据包: %1 秒\n").arg(header->ts.tv_sec);
        output += QString("捕获长度: %1 字节\n").arg(header->caplen);
        output += QString("实际长度: %1 字节\n").arg(header->len);

        std::cout << output.toStdString() << std::endl;

        // 将数据包内容打印到 GUI 中
        // instance->ui->textEdit->append(output);
    }

private:
    std::string target_device;
    std::string filter_expr;
    pcap_t *handle;
    bpf_u_int32 net, mask;
    bool capturing = false;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent)
    {
        setWindowTitle("Packet Sniffer");

        auto *layout = new QVBoxLayout;
        deviceComboBox = new QComboBox;
        startButton = new QPushButton("开始捕获");
        stopButton = new QPushButton("停止捕获");
        textEdit = new QTextEdit;

        layout->addWidget(deviceComboBox);
        layout->addWidget(startButton);
        layout->addWidget(stopButton);
        layout->addWidget(textEdit);

        auto *centralWidget = new QWidget(this);
        centralWidget->setLayout(layout);
        setCentralWidget(centralWidget);

        connect(startButton, &QPushButton::clicked, this, &MainWindow::startCapture);
        connect(stopButton, &QPushButton::clicked, this, &MainWindow::stopCapture);

        // 获取网络接口
        populateDevices();
    }

private slots:
    void startCapture()
    {
        QString device = deviceComboBox->currentText();
        QString filter = "tcp"; // 可以根据需要更改过滤条件

        captureThread = new QThread;
        packetCapture = new PacketCapture(device.toStdString(), filter.toStdString());
        packetCapture->moveToThread(captureThread);

        connect(captureThread, &QThread::started, packetCapture, &PacketCapture::startCapture);
        connect(this, &MainWindow::stopCaptureRequested, packetCapture, &PacketCapture::stopCapture);
        connect(captureThread, &QThread::finished, packetCapture, &QObject::deleteLater);
        connect(captureThread, &QThread::finished, captureThread, &QObject::deleteLater);
        captureThread->start();
    }

    void stopCapture()
    {
        emit stopCaptureRequested();
        captureThread->quit();
    }

private:
    void populateDevices()
    {
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            std::cerr << "无法获取网络接口: " << errbuf << std::endl;
            return;
        }

        for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
        {
            deviceComboBox->addItem(dev->name);
        }

        pcap_freealldevs(alldevs);
    }

    QComboBox *deviceComboBox;
    QPushButton *startButton;
    QPushButton *stopButton;
    QTextEdit *textEdit;
    PacketCapture *packetCapture;
    QThread *captureThread;

signals:
    void stopCaptureRequested();
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MainWindow mainWindow;
    mainWindow.show();
    return app.exec();
}