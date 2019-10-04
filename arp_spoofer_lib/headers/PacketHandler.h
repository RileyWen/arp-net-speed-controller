#ifndef ARP_SPOOFER_PACKETHANDLER_H
#define ARP_SPOOFER_PACKETHANDLER_H

#include <pcap.h>
#include <thread>
#include <cstring>
#include <string>

#include "concurrent_queue/headers/concurrent_queue.h"
#include "arp_spoofer_lib/headers/ByteCounter.h"

using std::thread;
using std::equal;
using std::string;
using std::strcat, std::strlen;

extern char pkt_handler_buf[128];
extern char forwarding_t_buf[128];

class PacketHandler {
private:
    typedef struct {
        u_int32_t len;
        u_char *packet_ptr;
    } _to_farward_pkt;

    typedef concurrent_queue<_to_farward_pkt> pkt_queue;
    typedef concurrent_queue<string> output_queue;

public:
    explicit PacketHandler(pcap_t *adapter, u_char self_mac[6],
                           u_char target_mac[6], u_char gateway_mac[6],
                           u_char target_ip[4], output_queue &output_q);

    void start();

    void stop();

    void set_drop_packet(bool v);

    void set_rate_limit_kBps(u_long v);

    const unsigned long &get_rate_cref() const;

private:
    static void packet_handler_f(u_char *param, const struct pcap_pkthdr *header,
                                 const u_char *pkt_data);

    void start_forwarding_thread();

    void stop_forwarding_thread();

    pcap_t *m_adapter;
    thread m_pcap_loop_t;
    thread m_pcap_forwarding_t;
    pkt_queue m_forwarded_pkt_queue = pkt_queue(100);
    output_queue &m_output_queue;

    unsigned long m_rate_limit_kBps;

    u_char m_target_ip[4];
    u_char m_self_mac[6];
    u_char m_target_mac[6];
    u_char m_gateway_mac[6];

    bool m_to_stop;
    bool m_to_stop_forwarding;
    bool m_will_drop_pkt;
};

#endif
