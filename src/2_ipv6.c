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

    PRV2(printf("\tPayload Length : %d\n",
                ntohs(ipv6_header->ip6_plen)),
         verbose);
    PRV2(printf("\tNext Header : %d\n", ipv6_header->ip6_nxt),
         verbose);

    PRV3(printf("\t\tTraffic Class : %d\n",
                ipv6_header->ip6_flow >> 8),
         verbose);
    PRV3(printf("\t\tFlow Label : %d\n", ipv6_header->ip6_flow >> 20),
         verbose);
    PRV3(printf("\t\tHop Limit: %d\n", ipv6_header->ip6_hops),
         verbose);

    return ipv6_header;
}