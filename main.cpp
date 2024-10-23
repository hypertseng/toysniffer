#include "../include/capture.h"
#include <iostream>
#include <pcap.h>

// 回调函数，用于处理捕获到的数据包
void captureCallback(const RawPacket &pkt)
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
    capture.callback = captureCallback;

    target_device = "en0";

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
   