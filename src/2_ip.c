#include "../include/2_ip.h"

struct iphdr *ip_analyzer(const u_char *packet, int verbose) {

    struct iphdr *ip = (struct iphdr *)packet;

    PRV1(printf(GRN "IP Header" NC "\n"), verbose);

    PRV1(printf("IP version : %d\n"
                "IHL: %d\n",
                ip->version, ip->ihl),
         verbose);

    if (ip->protocol == IPPROTO_TCP)
        PRV1(printf("Protocol : TCP\n"), verbose);

    if (ip->protocol == IPPROTO_UDP)
        PRV1(printf("Protocol : UDP\n"), verbose);

    PRV1(printf("IP source : %s\n",
                inet_ntoa(*(struct in_addr *)&ip->saddr)),
         verbose);

    PRV1(printf("IP destination : %s\n",
                inet_ntoa(*(struct in_addr *)&ip->daddr)),
         verbose);

    PRV2(printf("\tType of service : %d\n"
                "\tTotal length : %d\n"
                "\tTime to live : %d\n",
                ip->tos, ntohs(ip->tot_len), ip->ttl),
         verbose);

    PRV3(printf("\t\tIdentification : %d\n"
                "\t\tFragment offset : %d\n"
                "\t\tChecksum : %d\n",
                ntohs(ip->id), ip->frag_off, ntohs(ip->check)),
         verbose);

    return ip;
}