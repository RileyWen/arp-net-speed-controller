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
    explicit PacketHandler(pcap_t *adapter, u_char target_ip[4]);

    void start();

    void stop();

private:
    typedef struct {
        bool *to_stop;
        pcap_t *adapter;
        u_char *target_ip;
    } pkt_handler_args;

    static void packet_handler_f(u_char *param, const struct pcap_pkthdr *header,
                                 const u_char *pkt_data);

    thread m_pcap_loop_t;
    u_char m_target_ip[4];

    pcap_t *m_adapter;
    bool m_to_stop;
};

#endif
