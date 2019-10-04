#ifndef ARP_SPOOFER_COMMANDLINEARGPARSING_H
#define ARP_SPOOFER_COMMANDLINEARGPARSING_H

#include <sys/types.h>
#include <regex>
#include <getopt.h>
#include "arp_spoofer_lib/headers/net_structure.h"

using std::regex;

typedef struct CommandLineArgs_ {
    u_char target_ip[4];
    u_char target_mac[6];

    u_char gateway_ip[4];
    u_char gateway_mac[6];

    u_char self_ip[4];
    u_char self_mac[6];
} CommandLineArgs;

CommandLineArgs parse_cmd_args(int argc, char **argv);

#endif
