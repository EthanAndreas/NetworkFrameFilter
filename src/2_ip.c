#include "../include/2_ip.h"

/**
 * @brief Print informations contained in IPv4 header and return the
 * header in a structure
 * @return struct iphdr*
 */
struct iphdr *ip_analyzer(const u_char *packet, int verbose) {

    struct iphdr *ip = (struct iphdr *)packet;

    char *src_ip = inet_ntoa(*(struct in_addr *)&ip->saddr);
    char *dst_ip = inet_ntoa(*(struct in_addr *)&ip->daddr);

    // print mode for one line by frame
    int k;
    for (k = 0; k < strlen(src_ip); k++)
        PRV1(printf("%c", src_ip[k]), verbose);
    for (k = strlen(src_ip); k < 15; k++)
        PRV1(printf(" "), verbose);
    PRV1(printf("\t\t\t\t\t"), verbose);
    for (k = 0; k < strlen(dst_ip); k++)
        PRV1(printf("%c", dst_ip[k]), verbose);
    for (k = strlen(dst_ip); k < 15; k++)
        PRV1(printf(" "), verbose);
    PRV1(printf("\t\t\t\t\t"), verbose);

    PRV2(printf(YEL "IPv4" NC "\t\t"
                    "IP src : %s, ",
                inet_ntoa(*(struct in_addr *)&ip->saddr)),
         verbose);
    PRV2(printf("IP dst : %s, ",
                inet_ntoa(*(struct in_addr *)&ip->daddr)),
         verbose);

    PRV2(printf("Id : 0x%02x\n", ntohs(ip->id)), verbose);

    // all is printed
    PRV3(printf("\n" GRN "IPv4 Header" NC "\n"
                "IP source : %s\n"
                "IP destination : %s\n"
                "Identification : 0x%02x (%d)\n"
                "Type of service : 0x%02x (%d)\n"
                "Total length : %d\n"
                "Time to live : %d\n"
                "Fragment offset : 0x%02x (%d)\n"
                "Checksum : 0x%02x (%d)\n",
                src_ip, dst_ip, ntohs(ip->id), ntohs(ip->id), ip->tos,
                ip->tos, ntohs(ip->tot_len), ip->ttl, ip->frag_off,
                ip->frag_off, ntohs(ip->check), ntohs(ip->check)),
         verbose);

    return ip;
}