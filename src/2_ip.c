#include "../include/2_ip.h"

struct iphdr *ip_analyzer(const u_char *packet, int verbose) {

    struct iphdr *ip = (struct iphdr *)packet;

    PRV1(printf(GRN "IP Header" NC "\n"), verbose);

    PRV1(printf("IP version : %d", ip->version), verbose);

    if (ip->protocol == IPPROTO_TCP)
        PRV1(printf(", Protocol : TCP"), verbose);

    if (ip->protocol == IPPROTO_UDP)
        PRV1(printf(", Protocol : UDP"), verbose);

    PRV1(printf(", IP source : %s",
                inet_ntoa(*(struct in_addr *)&ip->saddr)),
         verbose);

    PRV1(printf(", IP destination : %s\n",
                inet_ntoa(*(struct in_addr *)&ip->daddr)),
         verbose);

    PRV2(printf("\tSize: %d\n"
                "\tThread size : %d\n",
                ip->ihl, ip->tot_len),
         verbose);

    PRV3(printf("\t\tType of service : %d\n"
                "\t\tIdentification : %d\n"
                "\t\tFragment offset : %d\n"
                "\t\tTime to live : %d\n"
                "\t\tChecksum : %d\n",
                ip->tos, ip->id, ip->frag_off, ip->ttl, ip->check),
         verbose);

    return ip;
}