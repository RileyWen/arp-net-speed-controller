#include "headers/net_structure.h"
#include "headers/PacketHandler.h"

void PacketHandler::packet_handler_f(u_char *param,
                                     const struct pcap_pkthdr *header,
                                     const u_char *pkt_data) {
    // Parse user parameters
    auto *args = (pkt_handler_args *) param;
    bool *to_stop = args->to_stop;
    pcap_t *adapter = args->adapter;
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

    if (equal(ih->destination_addr, ih->destination_addr + 3,
              target_ip)) {
        printf("To Target:\t%d.%d.%d.%d -> %d.%d.%d.%d\n",
               EXPAND_IP(ih->source_addr),
               EXPAND_IP(target_ip));
    }

    if (equal(ih->source_addr, ih->source_addr + 3,
              target_ip)) {
        printf("From Target:\t%d.%d.%d.%d -> %d.%d.%d.%d\n",
               EXPAND_IP(target_ip),
               EXPAND_IP(ih->destination_addr));
    }

    // TODO: Add Forwarding Part
}

void PacketHandler::start() {
    pkt_handler_args args;
    args.to_stop = &m_to_stop;
    args.adapter = m_adapter;
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

PacketHandler::PacketHandler(pcap_t *adapter, u_char target_ip[4])
        : m_adapter(adapter), m_to_stop(false) {
    std::copy(target_ip, target_ip + 4, m_target_ip);
}

