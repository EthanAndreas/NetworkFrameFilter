#include "../include/1_ethernet.h"

char *addr_mac_print(const struct ether_addr *addr, char *buf) {

    int ret_snprintf = snprintf(
        buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr->ether_addr_octet[0], addr->ether_addr_octet[1],
        addr->ether_addr_octet[2], addr->ether_addr_octet[3],
        addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

    if (ret_snprintf < 0) {

        printf("Error in addr_mac_print\n");
        exit(1);
    }

    return buf;
}

struct ether_header *ethernet_analyzer(const u_char *packet,
                                       int verbose) {

    struct ether_header *eth_header = (struct ether_header *)packet;

    printf(GRN "Ethernet Header" NC "\n");

    char buf[18];

    PRV1(printf(
             "Source MAC : %s\n",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_shost, buf)),
         verbose);

    PRV1(printf(
             "Destination MAC : %s\n",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_dhost, buf)),
         verbose);

    return eth_header;
}