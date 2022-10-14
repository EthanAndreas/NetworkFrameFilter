#include "../include/2_arp.h"

struct ether_arp *arp_analyzer(const u_char *packet) {

    struct ether_arp *arp = (struct ether_arp *)packet;

    printf("ARP Hardware type : %d, ARP Protocol type : %d, "
           "Address IP source : %s, Address IP destination : %s\n",

           ntohs(arp->arp_hrd), ntohs(arp->arp_pro),
           inet_ntoa(*(struct in_addr *)arp->arp_spa),
           inet_ntoa(*(struct in_addr *)arp->arp_tpa));

    return arp;
}