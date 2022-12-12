#include "../include/1_ethernet.h"

char *addr_mac_print(const struct ether_addr *addr, char *buf) {

    int ret_snprintf;

    NCHK(ret_snprintf = snprintf(
             buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr->ether_addr_octet[0], addr->ether_addr_octet[1],
             addr->ether_addr_octet[2], addr->ether_addr_octet[3],
             addr->ether_addr_octet[4], addr->ether_addr_octet[5]));

    return buf;
}

void add_mac_print_lvl1(struct ether_header *eth_header) {

    char buf[18];
    printf("%s\t\t\t\t",
           addr_mac_print(
               (struct ether_addr *)eth_header->ether_shost, buf));
    printf("%s\t\t\t\t",
           addr_mac_print(
               (struct ether_addr *)eth_header->ether_dhost, buf));
}

struct ether_header *ethernet_analyzer(const u_char *packet,
                                       int verbose) {

    struct ether_header *eth_header = (struct ether_header *)packet;

    char buf[18];

    // One line from the ethernet header
    PRV2(printf(
             GRN "Ethernet" NC "\tMac src : %s, ",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_shost, buf)),
         verbose);
    PRV2(printf(
             "Mac dst : %s\n",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_dhost, buf)),
         verbose);

    // Multiple lines from the ethernet header
    PRV3(printf(
             GRN "Ethernet Header" NC "\n"
                 "Source MAC : %s\n",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_shost, buf)),
         verbose);

    PRV3(printf(
             "Destination MAC : %s\n",
             addr_mac_print(
                 (struct ether_addr *)eth_header->ether_dhost, buf)),
         verbose);

    return eth_header;
}