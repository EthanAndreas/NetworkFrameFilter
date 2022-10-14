#include "../include/2_ip.h"

struct ip *ip_analyzer(const u_char *packet) {

    struct ip *ip = (struct ip *)packet;

    printf("IP version : %d, IP Size: %d, Thread size : %d, ",
           ip->ip_v, ip->ip_hl, ip->ip_len);

    if (ip->ip_p == IPPROTO_TCP)
        printf("Protocol : TCP\n");

    if (ip->ip_p == IPPROTO_UDP)
        printf("Protocol : UDP\n");

    printf("Address IP source : %s, Address IP destination : %s\n",
           inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    return ip;
}