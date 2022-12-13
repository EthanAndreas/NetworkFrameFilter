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

    // One line by frame
    PRV1(printf("%s\t"
                "%s\t",
                src_ip, dst_ip),
         verbose);

    // One line from the ipv6 header
    PRV2(printf(YEL "IPv6" NC "\t\t"
                    "IP src : %s, "
                    "IP dst : %s\n",
                src_ip, dst_ip),
         verbose);

    // Multiple lines from the ipv6 header
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

void get_protocol_ipv6(const u_char *packet,
                       struct ip6_hdr *ipv6_header, int length,
                       int verbose) {

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // TCP protocol
    switch (ipv6_header->ip6_nxt) {
    case IPPROTO_TCP:

        tcp_header = tcp_analyzer(packet, length, verbose);
        packet += tcp_header->th_off * 4;
        length -= tcp_header->th_off * 4;

        get_protocol_tcp(packet, tcp_header, length, verbose);
        break;

    // UDP protocol
    case IPPROTO_UDP:

        udp_header = udp_analyzer(packet, length, verbose);
        packet += sizeof(struct udphdr);
        length -= sizeof(struct udphdr);

        // Get the application layer protocol
        get_protocol_udp(packet, udp_header, length, verbose);
        break;

    // SCTP protocol
    case IPPROTO_SCTP:
        sctp_analyzer(packet, length, verbose);
        break;

    // Other protocols
    case IPPROTO_HOPOPTS:
        PRV1(printf("HOPOPTS\t\t\t-"), verbose);
        break;
    case IPPROTO_ROUTING:
        PRV1(printf("ROUTING\t\t\t-"), verbose);
        break;
    case IPPROTO_FRAGMENT:
        PRV1(printf("FRAGMENT\t\t-"), verbose);
        break;
    case IPPROTO_ICMPV6:
        PRV1(printf("ICMPV6\t\t\t-"), verbose);
        break;
    case IPPROTO_NONE:
        PRV1(printf("IPv6\t\t\t-"), verbose);
        break;
    case IPPROTO_DSTOPTS:
        PRV1(printf("DSTOPTS\t\t\t-"), verbose);
        break;
    case IPPROTO_MH:
        PRV1(printf("MH\t\t\t-"), verbose);
        break;

    default:
        PRV1(printf("-\t\t\t-"), verbose);
        break;
    }
}