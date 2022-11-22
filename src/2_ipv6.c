#include "../include/2_ipv6.h"

struct ip6_hdr *ipv6_analyzer(const u_char *packet, int verbose) {

    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;

    PRV1(printf(GRN "IPv6 Header" NC "\n"), verbose);

    PRV1(printf("Version: %d\n", ipv6_header->ip6_vfc >> 4), verbose);

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ip,
              INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ip,
              INET6_ADDRSTRLEN);

    PRV1(printf("Source IP : %s\n", src_ip), verbose);
    PRV1(printf("Destination IP : %s\n", dst_ip), verbose);

    PRV2(printf("\tPayload Length : %d\n"
                "\tNext Header : %d\n"
                "\tHop Limit: %d\n",
                ntohs(ipv6_header->ip6_plen), ipv6_header->ip6_nxt,
                ipv6_header->ip6_hops),
         verbose);

    PRV3(printf("\t\tTraffic Class : 0x%02x (%d)\n"
                "\t\tFlow Label : 0x%02x (%d)\n",
                ipv6_header->ip6_flow >> 8,
                ipv6_header->ip6_flow >> 8,
                ipv6_header->ip6_flow >> 20,
                ipv6_header->ip6_flow >> 20),
         verbose);

    return ipv6_header;
}