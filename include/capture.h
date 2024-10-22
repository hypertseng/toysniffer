#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <thread>
#include <atomic>
#include <functional>
#include <string>
#include <memory>

// 定义原始数据包结构
struct RawPacket
{
    std::unique_ptr<pcap_pkthdr> header;
    std::unique_ptr<u_char[]> data;
};

// 数据捕获类
class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    // 开始捕获
    bool startCapture(const std::string &interface, const std::string &filter);
    // 停止捕获
    void stopCapture();

    // 回调函数，用于传递捕获到的数据包
    std::function<void(const RawPacket &)> callback;

private:
    // pcap 回调处理函数
    static void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
    // 捕获线程函数
    void captureLoop();

    pcap_t *handle;
    std::thread captureThread;
    std::atomic<bool> running;
};

#endif // CAPTURE_H