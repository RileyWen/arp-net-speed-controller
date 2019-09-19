#ifndef ARP_PACKET_SENDER_H
#define ARP_PACKET_SENDER_H

#include <thread>
#include <functional>
#include <atomic>
#include <chrono>

#include <pcap.h>
#include "arp_spoofer_lib/headers/net_structure.h"

using std::function, std::bind;
using std::atomic;
using std::thread, std::this_thread::sleep_for;
using std::chrono::milliseconds;
using std::ref;

class ARP_packet_sender {
public:
    ARP_packet_sender(pcap_t *adapter, arp_packet *packet,
                      int interval_milli_sec);

    void set_interval(int new_interval_milli_sec);

    void start();

    void stop();

private:
    int m_interval;    // Interval between sending each packet
    bool m_stop;
    thread m_packet_sending_t;
    pcap_t *m_adapter;
    arp_packet *m_packet;

    void m_packet_sending_f(pcap_t *adapter, arp_packet *packet,
                            int &interval_milli_sec);
};

#endif
