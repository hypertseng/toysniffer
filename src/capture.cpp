#include "capture.h"
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>

PacketCapture::PacketCapture() : handle(nullptr), running(false) {}

PacketCapture::~PacketCapture()
{
    stopCapture();
}

bool PacketCapture::startCapture(const std::string &interface, const std::string &filterExp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // 打开网络接口进行捕获
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "无法打开设备 " << interface << ": " << errbuf << std::endl;
        return false;
    }

    // 编译过滤器表达式
    if (pcap_compile(handle, &fp, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "无法编译过滤器 " << filterExp << ": " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        handle = nullptr;
        return false;
    }

    // 设置过滤器
    if (pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "无法设置过滤器 " << filterExp << ": " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        handle = nullptr;
        return false;
    }

    pcap_freecode(&fp);
    running = true;

    // 使用 lambda 表达式启动线程
    captureThread = std::thread([this]()
                                { this->captureLoop(); });

    return true;
}

void PacketCapture::stopCapture()
{
    if (running)
    {
        running = false;
        pcap_breakloop(handle);
        if (captureThread.joinable())
        {
            captureThread.join();
        }
        pcap_close(handle);
        handle = nullptr;
    }
}

void PacketCapture::captureLoop()
{
    pcap_loop(handle, 0, PacketCapture::packetHandler, reinterpret_cast<u_char *>(this));
}

void PacketCapture::packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketCapture *self = reinterpret_cast<PacketCapture *>(user);
    if (self->callback)
    {
        // 创建 RawPacket，并使用智能指针管理内存
        RawPacket pkt;
        pkt.header = std::make_unique<pcap_pkthdr>(*header);
        pkt.data = std::make_unique<u_char[]>(header->caplen);
        std::memcpy(pkt.data.get(), packet, header->caplen);

        // 调用回调函数处理包
        self->callback(pkt);
    }
}
