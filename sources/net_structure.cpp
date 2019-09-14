#include "headers/net_structure.h"

arp_packet *arp_packet_constructor(u_char *sender_ip, u_char *sender_mac, u_char *receiver_ip, u_char *receiver_mac,
                                   u_char *target_ip) {
    arp_packet *p_new_arp_packet = new arp_packet;

    // Fill up ethernet header
    std::copy(sender_mac, sender_mac + 6, p_new_arp_packet->eth_hdr.src_mac);
    std::copy(receiver_mac, receiver_mac + 6, p_new_arp_packet->eth_hdr.dst_mac);
    p_new_arp_packet->eth_hdr.type = htons(0x0806);     // Type is ARP

    p_new_arp_packet->arp_hdr.hardware_type = htons(0x0001);            // 0x0001 -> Ethernet
    p_new_arp_packet->arp_hdr.proto_type = htons(0x0800);               // 0x0800 -> IPv4
    p_new_arp_packet->arp_hdr.hardware_size = 0x06;                     // 0x06 -> size of MAC
    p_new_arp_packet->arp_hdr.proto_size = 0x04;                        // 0x04 -> size of IP
    p_new_arp_packet->arp_hdr.opcode = htons(0x0002);               // 0x0002 -> ARP reply

    // 'target_ip' is at 'sender_mac'
    std::copy(sender_mac, sender_mac + 6, p_new_arp_packet->arp_hdr.src_mac);
    std::copy(target_ip, target_ip + 4, p_new_arp_packet->arp_hdr.src_ip);

    std::copy(receiver_mac, receiver_mac + 6, p_new_arp_packet->arp_hdr.dst_mac);
    std::copy(receiver_ip, receiver_ip + 4, p_new_arp_packet->arp_hdr.dst_ip);
}
