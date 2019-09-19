#ifndef ARP_SPOOFER_ADAPTERQUERY_H
#define ARP_SPOOFER_ADAPTERQUERY_H

#include <pcap.h>
#include <string>
#include <vector>
#include <iostream>

using std::string, std::vector, std::cin, std::cout;

string list_dev_and_choose_dev();

pcap_t *open_adapter(string &adapter);

#endif
