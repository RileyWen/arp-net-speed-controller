#include "headers/ARPSpoofing.h"

ARP_packet_sender::ARP_packet_sender(pcap_t *adapter, arp_packet *packet,
                                     int interval_milli_sec) {
    m_stop = false;
    m_interval = interval_milli_sec;
    m_adapter = adapter;
    m_packet = packet;
}

void ARP_packet_sender::m_packet_sending_f(pcap_t *adapter,
                                           arp_packet *packet,
                                           int &interval_milli_sec) {
    while (true) {
        if (m_stop)
            return;

        printf("Sending packet...\n");

        // Send down the deceive_dst_packet
        if (pcap_sendpacket(adapter,                    // Adapter
                            (const u_char *) packet,   // buffer with the deceive_dst_packet
                            sizeof(arp_packet)  // size
        ) != 0) {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adapter));
            return;
        }

        // sleep for 'interval' milliseconds
        sleep_for(milliseconds(interval_milli_sec));
    }
}

void ARP_packet_sender::set_interval(int new_interval) {
    m_interval = new_interval;
}

void ARP_packet_sender::start() {
    stop();
//    auto member_func_bind_f = [this](pcap_t *_m_adapter, arp_packet *_m_packet,
//                                       int &_interval_milli_sec){
//        m_packet_sending_f(_m_adapter, _m_packet, _interval_milli_sec);
//    };
//    m_packet_sending_t = thread(member_func_bind_f, m_adapter, m_packet, ref(m_interval));
    printf("starting...\n");
    m_packet_sending_t = thread(&ARP_packet_sender::m_packet_sending_f, this,
                                m_adapter, m_packet, ref(m_interval));
}

void ARP_packet_sender::stop() {
    if (m_packet_sending_t.joinable()) {
        m_stop = true;
        m_packet_sending_t.join();
    }
    m_stop = false;
}
