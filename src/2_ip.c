#include "../include/2_ip.h"

/**
 * @brief Print informations contained in IPv4 header and return the
 * header in a structure
 * @return struct iphdr*
 */
struct iphdr *ip_analyzer(const u_char *packet, int verbose) {

    struct iphdr *ip = (struct iphdr *)packet;

    PRV1(printf("\n" GRN "IPv4 Header" NC "\n"), verbose);

    PRV1(printf("IP source : %s\n",
                inet_ntoa(*(struct in_addr *)&ip->saddr)),
         verbose);

    PRV1(printf("IP destination : %s\n",
                inet_ntoa(*(struct in_addr *)&ip->daddr)),
         verbose);

    PRV2(printf("\tType of service : 0x%02x (%d)\n"
                "\tTotal length : %d\n"
                "\tTime to live : %d\n",
                ip->tos, ip->tos, ntohs(ip->tot_len), ip->ttl),
         verbose);

    PRV3(printf("\t\tIdentification : 0x%02x (%d)\n"
                "\t\tFragment offset : 0x%02x (%d)\n"
                "\t\tChecksum : 0x%02x (%d)\n",
                ntohs(ip->id), ntohs(ip->id), ip->frag_off,
                ip->frag_off, ntohs(ip->check), ntohs(ip->check)),
         verbose);

    return ip;
}