#include "../include/ethernet.h"

char *ether_ntoa_r(const struct ether_addr *addr, char *buf) {

    int ret_snprintf = snprintf(
        buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr->ether_addr_octet[0], addr->ether_addr_octet[1],
        addr->ether_addr_octet[2], addr->ether_addr_octet[3],
        addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

    if (ret_snprintf < 0) {

        printf("Error in ether_ntoa_r\n");
        exit(1);
    }

    return buf;
}

struct ether_header *ethernet_analyzer(const u_char *packet) {

    static char buf[18];
    struct ether_header *eth_header = (struct ether_header *)packet;

    printf("Ethernet Header :\n"
           "Address MAC source : %s, Address MAC destination : %s\n",
           ether_ntoa_r((struct ether_addr *)eth_header->ether_shost,
                        buf),
           ether_ntoa_r((struct ether_addr *)eth_header->ether_dhost,
                        buf));

    return eth_header;
}