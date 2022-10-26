#include "../include/2_ip.h"

struct ip *ip_analyzer(const u_char *packet, int verbose) {

    struct ip *ip = (struct ip *)packet;

    PRV1(printf("IP version : %d", ip->ip_v), verbose);

    if (ip->ip_p == IPPROTO_TCP)
        PRV1(printf(", Protocol : TCP"), verbose);

    if (ip->ip_p == IPPROTO_UDP)
        PRV1(printf(", Protocol : UDP"), verbose);

    PRV1(
        printf(
            ", Address IP source : %s, Address IP destination : %s\n",
            inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst)),
        verbose);

    PRV2(printf("IP Size: %d, Thread size : %d\n", ip->ip_hl,
                ip->ip_len),
         verbose);

    return ip;
}