#include "arp_spoofer_lib/headers/AdapterQuery.h"
#include <unistd.h>

string list_dev_and_choose_dev() {
    vector<string> dev_names;
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if (pcap_findalldevs(&interfaces, error) == -1) {
        fprintf(stderr, "\nerror in pcap findall devs\n");
        _exit(1);
    }

    printf("the interfaces present on the system are:");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("\n%d:  %s", i++, temp->name);
        dev_names.emplace_back(temp->name);
    }
    printf("\nEnter the Device Index: ");

    int choice;
    while (true) {
        scanf("%d", &choice);
        if (choice >= 0 && choice < dev_names.size())
            break;
        else
            printf("Invalid input! Reenter the Index: ");
    }

    pcap_freealldevs(interfaces);

    return dev_names[choice];
}

pcap_t *open_adapter(string &adapter) {
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    fp = pcap_open_live(adapter.c_str(),      // name of the device
                        65536,    // portion of the packet to capture.
            // 65536 grants that the whole packet will be captured on all the MACs.
                        1,        // promiscuous mode (nonzero means promiscuous)
                        10,       // read timeout
                        errbuf    // error buffer
    );

    if (fp == nullptr) {
        fprintf(stderr, "Unable to open %s.\n", adapter.c_str());
        _exit(1);
    } else {
        printf("Successfully opened %s\n", adapter.c_str());
        return fp;
    }
}
