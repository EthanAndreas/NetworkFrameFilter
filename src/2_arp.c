#include "../include/2_arp.h"

struct ether_arp *arp_analyzer(const u_char *packet, int verbose) {

    struct ether_arp *arp = (struct ether_arp *)packet;

    PRV1(printf(
             "Address IP source : %s, Address IP destination : %s\n",
             inet_ntoa(*(struct in_addr *)arp->arp_spa),
             inet_ntoa(*(struct in_addr *)arp->arp_tpa)),
         verbose);

    PRV2(printf("ARP Hardware type : %d, ARP Protocol type : %d\n",
                ntohs(arp->arp_hrd), ntohs(arp->arp_pro)),
         verbose);

    return arp;
}