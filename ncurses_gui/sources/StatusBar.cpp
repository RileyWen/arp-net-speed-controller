#include "ncurses_gui/headers/StatusBar.h"

void StatusBar::set_pkt_policy(StatusBar::PktPolicy policy) {
    m_current_pkt_policy = policy;
}

void StatusBar::append_char_to_input_buf(char ch) {
    m_input_buf += ch;
}

void StatusBar::pop_last_of_input_buf() {
    if (!m_input_buf.empty())
        m_input_buf.pop_back();
}

string StatusBar::get_status_bar_str(int win_length) {
    string status_bar_str;
    const static string echo_mode_shortcut_help("<F1> Forward | <F2> Drop | <F3> Limit Rate");
    const static string input_mode_shortcut_help("<Esc> Go Back | <Enter> Set the rate");

    switch (m_current_pkt_policy) {
        case PktPolicy::Drop: {
            const static string dropping_mode_str("[Dropping Mode]");
            status_bar_str.append(dropping_mode_str);
            status_bar_str.append(win_length - dropping_mode_str.size() - echo_mode_shortcut_help.size(), ' ');
            status_bar_str.append(echo_mode_shortcut_help);
            break;
        }
        case PktPolicy::Forward: {
            const static string forwarding_mode_str("[Forwarding Mode]");
            status_bar_str.append(forwarding_mode_str);
            status_bar_str.append(win_length - forwarding_mode_str.size() - echo_mode_shortcut_help.size(), ' ');
            status_bar_str.append(echo_mode_shortcut_help);
            break;
        }
        case PktPolicy::LimitRate: {
            char tmp_buf[64];
            snprintf(tmp_buf, 64, "[Rate Limiting Mode]: Limit to %6lu KBps", m_rate_cref / 1024);
            int tmp_buf_len = strlen(tmp_buf);
            status_bar_str.append(tmp_buf);
            status_bar_str.append(win_length - tmp_buf_len - echo_mode_shortcut_help.size(), ' ');
            status_bar_str.append(echo_mode_shortcut_help);
            break;
        }
        case PktPolicy::EnteringRateValue: {
            const static string enter_prompt("Enter the rate limit in KBps: ");
            status_bar_str.append(enter_prompt);
            status_bar_str.append(m_input_buf);
            status_bar_str.append(win_length - m_input_buf.size() - enter_prompt.size()
                                  - input_mode_shortcut_help.size(), ' ');
            status_bar_str.append(input_mode_shortcut_help);
        }
    }

    return std::move(status_bar_str);
}

StatusBar::PktPolicy StatusBar::get_pkt_policy() const {
    return m_current_pkt_policy;
}

void StatusBar::clear_input_buf() {
    m_input_buf.erase();
}

u_long StatusBar::read_input_buf_as_num() {
    unsigned long v;
    try {
        v = std::stoul(m_input_buf);
    } catch (std::exception &e) {
        v = ulong_limits::max();
    }
    return v;
}
