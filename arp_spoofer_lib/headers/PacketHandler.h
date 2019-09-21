#ifndef ARP_SPOOFER_PACKETHANDLER_H
#define ARP_SPOOFER_PACKETHANDLER_H

#include <pcap.h>
#include <thread>
#include <string>
#include <memory>

#include "concurrent_queue/headers/concurrent_queue.h"

using std::thread;
using std::string;
using std::equal;
using std::shared_ptr, std::make_shared;

class PacketHandler {
public:
    explicit PacketHandler(pcap_t *adapter, u_char self_mac[6],
                           u_char target_mac[6], u_char gateway_mac[6],
                           u_char target_ip[4]);

    void start();

    void stop();

    void set_drop_packet(bool v);

private:
    typedef struct {
        u_int32_t len;
        u_char packet[1500];
    } _to_farward_pkt;

    typedef concurrent_queue<shared_ptr<_to_farward_pkt>> pkt_queue;

    typedef struct {
        bool *to_stop;
        bool *will_drop_pkt;
        pcap_t *adapter;
        u_char *self_mac;
        u_char *target_mac;
        u_char *gateway_mac;
        u_char *target_ip;
        pkt_queue *forwarded_pkt_queue;
    } pkt_handler_args;

    static void packet_handler_f(u_char *param, const struct pcap_pkthdr *header,
                                 const u_char *pkt_data);

    void start_forwarding_thread();

    void stop_forwarding_thread();

    pcap_t *m_adapter;
    thread m_pcap_loop_t;
    thread m_pcap_forwarding_t;
    pkt_queue m_forwarded_pkt_queue;

    u_char m_target_ip[4];
    u_char m_self_mac[6];
    u_char m_target_mac[6];
    u_char m_gateway_mac[6];

    bool m_to_stop;
    bool m_to_stop_forwarding;
    bool m_will_drop_pkt;
};

#endif
