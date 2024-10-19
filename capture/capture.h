#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <thread>
#include <atomic>
#include <functional>

struct RawPacket
{
    struct pcap_pkthdr *header;
    const u_char *data;
};

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    bool startCapture(const std::string &interface, const std::string &filter);
    void stopCapture();

    // Callback to deliver captured packets
    std::function<void(const RawPacket &)> onPacketCaptured;

private:
    static void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
    void captureLoop();

    pcap_t *handle;
    std::thread captureThread;
    std::atomic<bool> running;
};

#endif // CAPTURE_H