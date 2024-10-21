#include "capture.h"
#include <iostream>
#include <pcap.h>

// 回调函数，用于处理捕获到的数据包
void myPacketCaptured(const RawPacket &pkt)
{
    std::cout << "捕获到一个数据包: " << std::endl;
    std::cout << "时间戳: " << pkt.header->ts.tv_sec << " 秒" << std::endl;
    std::cout << "捕获长度: " << pkt.header->caplen << " 字节" << std::endl;
    std::cout << "实际长度: " << pkt.header->len << " 字节" << std::endl;

    // 打印数据包前几个字节
    std::cout << "数据包内容 (前16字节): ";
    for (size_t i = 0; i < std::min(pkt.header->caplen, static_cast<uint32_t>(16)); ++i)
    {
        printf("%02x ", pkt.data[i]);
    }
    std::cout << std::endl;
}

int main()
{
    PacketCapture capture;
    char errbuf[PCAP_ERRBUF_SIZE]; /* error string */
    pcap_if_t *dev = nullptr;
    pcap_if_t *alldevs;
    char *target_device = nullptr; // 目标网络接口
    bpf_u_int32 net;  // 网络地址
    bpf_u_int32 mask; // 子网掩码

    // 设置捕获数据包的回调函数
    capture.callback = myPacketCaptured;

    // 获取所有网络接口
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "无法获取网络接口: " << errbuf << std::endl;
        return 1;
    }

    // 2. 打印所有可用的网络接口
    std::cout << "可用的网络接口:\n";
    int i = 0;
    for (dev = alldevs; dev != nullptr; dev = dev->next)
    {
        std::cout << ++i << ": " << dev->name;
        if (dev->description)
        {
            std::cout << " (" << dev->description << ")";
        }
        std::cout << std::endl;
    }

    // 选择网络接口进行抓包
    if (i == 0)
    {
        std::cerr << "没有可用的网络接口" << std::endl;
        return 1;
    }

    target_device = "en0";

    // 获取设备的网络地址和子网掩码
    // if (pcap_lookupnet(alldevs->name, &net, &mask, errbuf) == -1)
    if (pcap_lookupnet(target_device, &net, &mask, errbuf) == -1)
    {
        std::cerr << "无法获取设备 " << alldevs->name << " 的网络地址和子网掩码: " << errbuf << std::endl;
        net = 0;
        mask = 0;
    }

    // 打印网络地址和子网掩码
    // std::cout << "设备 " << alldevs->name << " 的网络地址: " << net << std::endl;
    // std::cout << "设备 " << alldevs->name << " 的子网掩码: " << mask << std::endl;

    std::string filter = "tcp";     // 设置一个简单的过滤器表达式，捕获 TCP 数据包

    if (!capture.startCapture(target_device, filter))
    {
        std::cerr << "无法开始捕获数据包" << std::endl;
        return 1;
    }

    std::cout << "正在捕获数据包，按 Ctrl+C 停止..." << std::endl;

    // 等待一定时间后停止捕获，模拟用户停止捕获操作
    std::this_thread::sleep_for(std::chrono::seconds(10));
    capture.stopCapture();

    std::cout << "捕获结束。" << std::endl;

    return 0;
}
   