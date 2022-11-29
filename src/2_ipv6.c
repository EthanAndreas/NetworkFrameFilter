#include "../include/2_ipv6.h"

/**
 * @brief Print informations contained in IPv6 header and return the
 * header in a structure
 * @return struct iphdr*
 */
struct ip6_hdr *ipv6_analyzer(const u_char *packet, int verbose) {

    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ip,
              INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ip,
              INET6_ADDRSTRLEN);

    if (verbose == 1) {

        int k;
        if (strlen(src_ip) != INET6_ADDRSTRLEN) {
            for (k = strlen(src_ip); k < INET6_ADDRSTRLEN; k++)
                src_ip[k] = ' ';
            src_ip[k] = '\0';
        }
        if (strlen(dst_ip) != INET6_ADDRSTRLEN) {
            for (k = strlen(dst_ip); k < INET6_ADDRSTRLEN; k++)
                dst_ip[k] = ' ';
            dst_ip[k] = '\0';
        }
    }

    PRV1(printf("%s\t"
                "%s\t",
                src_ip, dst_ip),
         verbose);

    PRV2(printf(YEL "IPv6" NC "\t\t"
                    "IP src : %s, "
                    "IP dst : %s\n",
                src_ip, dst_ip),
         verbose);

    PRV3(printf("\n" GRN "IPv6 Header" NC "\n"
                "Source IP : %s\n"
                "Destination IP : %s\n"
                "Payload Length : %d\n"
                "Next Header : %d\n"
                "Hop Limit: %d\n"
                "Traffic Class : 0x%02x (%d)\n"
                "Flow Label : 0x%02x (%d)\n",
                src_ip, dst_ip, ntohs(ipv6_header->ip6_plen),
                ipv6_header->ip6_nxt, ipv6_header->ip6_hops,
                ipv6_header->ip6_flow >> 8,
                ipv6_header->ip6_flow >> 8,
                ipv6_header->ip6_flow >> 20,
                ipv6_header->ip6_flow >> 20),
         verbose);

    return ipv6_header;
}