#include "ncurses_gui/headers/CommandLineArgParsing.h"

CommandLineArgs parse_cmd_args(int argc, char **argv) {
    static struct option long_opts[] = {
            {"target-ip",   required_argument, nullptr, 'T'},
            {"target-mac",  required_argument, nullptr, 't'},
            {"gateway-ip",  required_argument, nullptr, 'G'},
            {"gateway-mac", required_argument, nullptr, 'g'},
            {"self-ip",     required_argument, nullptr, 'S'},
            {"self-mac",    required_argument, nullptr, 's'},
            {"help",        no_argument,       nullptr, 'h'},
            {0, 0,                             0,       0}
    };

    regex ip_regex(R"(^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)");
    regex mac_regex(R"(^([0-9a-fA-F]{1,2}[\.:\-]){5}[0-9a-fA-F]{1,2}$)");

    CommandLineArgs cmd_args = {};

    enum ARG_INDEX {
        T = 0, G, S, t, g, s
    };
    bool arg_found[6] = {};
    static char arg_ch[6] = {'T', 'G', 'S', 't', 'g', 's'};

    int opt, opt_i = 0, ret;
    while ((opt = getopt_long(argc, argv, "T:G:S:t:g:s:h", long_opts, &opt_i))) {
        if (opt == -1)
            break;

        switch (opt) {
            case 'h':
                exit(0);
                break;
            case 'T':
                if (!std::regex_match(optarg, ip_regex))
                    goto PARSE_FAILED;
                sscanf(optarg, "%3hhu%*[.]%3hhu%*[.]%3hhu%*[.]%3hhu",
                       EXPAND_IP_FOR_INPUT(cmd_args.target_ip));
                arg_found[ARG_INDEX::T] = true;
                break;
            case 'G':
                if (!std::regex_match(optarg, ip_regex))
                    goto PARSE_FAILED;
                sscanf(optarg, "%3hhu%*[.]%3hhu%*[.]%3hhu%*[.]%3hhu",
                       EXPAND_IP_FOR_INPUT(cmd_args.gateway_ip));
                arg_found[ARG_INDEX::G] = true;
                break;
            case 'S':
                if (!std::regex_match(optarg, ip_regex))
                    goto PARSE_FAILED;
                sscanf(optarg, "%3hhu%*[.]%3hhu%*[.]%3hhu%*[.]%3hhu",
                       EXPAND_IP_FOR_INPUT(cmd_args.self_ip));
                arg_found[ARG_INDEX::S] = true;
                break;
            case 't':
                if (!std::regex_match(optarg, mac_regex))
                    goto PARSE_FAILED;
                sscanf(optarg, "%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx",
                       EXPAND_MAC_FOR_INPUT(cmd_args.target_mac));
                arg_found[ARG_INDEX::t] = true;
                break;
            case 'g':
                if (!std::regex_match(optarg, mac_regex))
                    goto PARSE_FAILED;
                ret = sscanf(optarg, "%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx",
                             EXPAND_MAC_FOR_INPUT(cmd_args.gateway_mac));
                arg_found[ARG_INDEX::g] = true;
                break;
            case 's':
                if (!std::regex_match(optarg, mac_regex))
                    goto PARSE_FAILED;
                sscanf(optarg, "%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx%*[:-.]%2hhx",
                       EXPAND_MAC_FOR_INPUT(cmd_args.self_mac));
                arg_found[ARG_INDEX::s] = true;
                break;
            default:
                goto PARSE_FAILED;
        }
    }

    for (int i = 0; i < 6; i++) {
        if (!arg_found[i]) {
            printf("Argument -%c must be supplied.\n", arg_ch[i]);
            goto NOT_ENOUGH_ARGS;
        }
    }

#ifdef DEBUG
    printf("-T: %hhu.%hhu.%hhu.%hhu\n", EXPAND_IP(cmd_args.target_ip));
    printf("-G: %hhu.%hhu.%hhu.%hhu\n", EXPAND_IP(cmd_args.gateway_ip));
    printf("-S: %hhu.%hhu.%hhu.%hhu\n", EXPAND_IP(cmd_args.self_ip));
    printf("-t: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", EXPAND_MAC(cmd_args.target_mac));
    printf("-g: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", EXPAND_MAC(cmd_args.gateway_mac));
    printf("-s: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", EXPAND_MAC(cmd_args.self_mac));
#endif

    return cmd_args;

    PARSE_FAILED:
    printf("Invalid command line arguments or formats.\n");

    NOT_ENOUGH_ARGS:
    static
    char usage[] = "\nUsage:\n"
                   "-T --target-ip=<target IP>             'Target' is the device you want to attack\n"
                   "-t --target-mac=<target MAC>\n"
                   "-G --gateway-ip=<gateway IP>           'Gateway' is often the router in your subnet\n"
                   "-g --gateway-mac=<gateway MAC>\n"
                   "-S --self-ip=<IP of this device>       'Self' means the device running this program\n"
                   "-s --self-mac=<MAC of this device>\n"
                   "-h --help                              Print this help info\n";

    printf("%s", usage);
    exit(0);
}
