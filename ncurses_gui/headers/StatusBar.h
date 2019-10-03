#ifndef ARP_SPOOFER_STATUSBAR_H
#define ARP_SPOOFER_STATUSBAR_H

#include <string>
#include <cstring>
#include <exception>
#include <limits>

typedef unsigned long u_long;

using std::string;
using std::strlen, std::snprintf;
using ulong_limits = std::numeric_limits<u_long>;

class StatusBar {
public:
    enum PktPolicy {
        Drop = 0,
        Forward,
        LimitRate,
        EnteringRateValue
    };

    explicit StatusBar(const unsigned long &rate_cref)
            : m_rate_cref(rate_cref) {}

    void set_pkt_policy(PktPolicy policy);

    [[nodiscard]] PktPolicy get_pkt_policy() const;

    void append_char_to_input_buf(char ch);

    void pop_last_of_input_buf();

    void clear_input_buf();

    u_long read_input_buf_as_num();

    string get_status_bar_str(int win_length);

private:
    PktPolicy m_current_pkt_policy = PktPolicy::Forward;
    string m_input_buf;
    const unsigned long &m_rate_cref;
};

#endif
