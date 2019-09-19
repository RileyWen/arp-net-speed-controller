#ifndef ARP_SPOOFER_PACKETHANDLER_H
#define ARP_SPOOFER_PACKETHANDLER_H

#include <pcap.h>
#include <thread>
#include <string>

using std::thread;
using std::string;
using std::equal;

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
        bool *to_stop;
        bool *will_drop_pkt;
        pcap_t *adapter;
        u_char *self_mac;
        u_char *target_mac;
        u_char *gateway_mac;
        u_char *target_ip;
    } pkt_handler_args;

    static void packet_handler_f(u_char *param, const struct pcap_pkthdr *header,
                                 const u_char *pkt_data);

    pcap_t *m_adapter;
    thread m_pcap_loop_t;

    u_char m_target_ip[4];
    u_char m_self_mac[6];
    u_char m_target_mac[6];
    u_char m_gateway_mac[6];

    bool m_to_stop;
    bool m_will_drop_pkt;
};

#endif
