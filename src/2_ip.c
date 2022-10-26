#include "../include/2_ip.h"

struct ip *ip_analyzer(const u_char *packet, int verbose) {

    struct ip *ip = (struct ip *)packet;

    PRV1(printf(GRN "IP Header" NC "\n"), verbose);

    PRV1(printf("IP version : %d\n", ip->ip_v), verbose);

    if (ip->ip_p == IPPROTO_TCP)
        PRV1(printf("Protocol : TCP\n"), verbose);

    if (ip->ip_p == IPPROTO_UDP)
        PRV1(printf("Protocol : UDP\n"), verbose);

    PRV1(printf("Address IP source : %s\n", inet_ntoa(ip->ip_src)),
         verbose);

    PRV1(printf("Address IP destination : %s\n",
                inet_ntoa(ip->ip_dst)),
         verbose);

    PRV2(printf("\tIP Size: %d\n"
                "\tThread size : %d\n",
                ip->ip_hl, ip->ip_len),
         verbose);

    // type service

    return ip;
}