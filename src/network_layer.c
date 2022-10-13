#include "../include/network_layer.h"

struct ip *ip_analyzer(const u_char *packet) {

    struct ip *ip =
        (struct ip *)(packet + sizeof(struct ether_header));

    printf("IP version : %d, IP Size: %d, Thread size : %d, "
           "Protocol : %d\n"
           "Address IP source : %s, Address IP destination : %s\n",
           ip->ip_v, ip->ip_hl, ip->ip_len, ip->ip_p,
           inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    return ip;
}

struct ether_arp *arp_analyzer(const u_char *packet) {

    char buf[18];
    struct ether_arp *arp =
        (struct ether_arp *)(packet + sizeof(struct ether_header));

    printf("ARP Hardware type : %d, ARP Protocol type : %d, "
           "Address IP source : %s, Address IP destination : %s\n"
           "Address MAC source : %s, Address MAC destination : %s\n",

           ntohs(arp->arp_hrd), ntohs(arp->arp_pro),
           inet_ntoa(*(struct in_addr *)arp->arp_spa),
           inet_ntoa(*(struct in_addr *)arp->arp_tpa),
           ether_ntoa_r((struct ether_addr *)arp->arp_sha, buf),
           ether_ntoa_r((struct ether_addr *)arp->arp_tha, buf));

    return arp;
}