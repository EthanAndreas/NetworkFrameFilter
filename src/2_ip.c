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

    // One line by frame
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

    // One line from the ipv4 header
    PRV2(printf(YEL "IPv4" NC "\t\t"
                    "IP src : %s, ",
                inet_ntoa(*(struct in_addr *)&ip->saddr)),
         verbose);
    PRV2(printf("IP dst : %s, ",
                inet_ntoa(*(struct in_addr *)&ip->daddr)),
         verbose);

    PRV2(printf("Id : 0x%02x\n", ntohs(ip->id)), verbose);

    // Multiple lines from the ipv4 header
    PRV3(printf("\n" GRN "IPv4 Header" NC "\n"
                "IP source : %s\n"
                "IP destination : %s\n"
                "IHL : %d\n"
                "Identification : 0x%02x (%d)\n"
                "Type of service : 0x%02x (%d)\n"
                "Total length : %d\n"
                "Time to live : %d\n"
                "Fragment offset : 0x%02x (%d)\n"
                "Protocol : %d\n"
                "Checksum : 0x%02x (%d)\n",
                src_ip, dst_ip, ip->ihl, (ip->id), ntohs(ip->id),
                ip->tos, ip->tos, ntohs(ip->tot_len), ip->ttl,
                ip->frag_off, ip->frag_off, ip->protocol,
                ntohs(ip->check), ntohs(ip->check)),
         verbose);

    return ip;
}

void get_protocol_ip(const u_char *packet, struct iphdr *ip_header,
                     int length, int verbose) {

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    switch (ip_header->protocol) {

    // TCP protocol
    case IPPROTO_TCP:
        tcp_header = tcp_analyzer(packet, length, verbose);
        packet += tcp_header->th_off * 4;
        length -= tcp_header->th_off * 4;

        // Get the application layer protocol
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

    // IPIP protocol
    case IPPROTO_IPIP:
        // avoid print twice ipv4 in verbose level 1
        if (verbose == 1)
            verbose = 0;

        ip_header = ip_analyzer(packet, verbose);
        packet += ip_header->ihl * 4;
        length -= ip_header->ihl * 4;

        // avoid print twice ipv4 in verbose level 1
        if (verbose == 0)
            verbose = 1;

        get_protocol_ip(packet, ip_header, length, verbose);
        break;

    // IPv6 protocol
    case IPPROTO_IPV6:
        ipv6_analyzer(packet, verbose);
        break;

    // ICMP protocol
    case IPPROTO_ICMP:
        icmp_analyzer(packet, length, verbose);
        break;

    // Other protocols
    case IPPROTO_IGMP:
        PRV1(printf("-\t\t\tIGMP"), verbose);
        break;
    case IPPROTO_EGP:
        PRV1(printf("-\t\t\tEGP"), verbose);
        break;
    case IPPROTO_PUP:
        PRV1(printf("-\t\t\tPUP"), verbose);
        break;
    case IPPROTO_IDP:
        PRV1(printf("-\t\t\tIDP"), verbose);
        break;
    case IPPROTO_TP:
        PRV1(printf("-\t\t\tTP"), verbose);
        break;
    case IPPROTO_DCCP:
        PRV1(printf("-\t\t\tDCCP"), verbose);
        break;
    case IPPROTO_RSVP:
        PRV1(printf("-\t\t\tRSVP"), verbose);
        break;
    case IPPROTO_GRE:
        PRV1(printf("-\t\t\tGRE"), verbose);
        break;
    case IPPROTO_ESP:
        PRV1(printf("-\t\t\tESP"), verbose);
        break;
    case IPPROTO_AH:
        PRV1(printf("-\t\t\tAH"), verbose);
        break;
    case IPPROTO_MTP:
        PRV1(printf("-\t\t\tMTP"), verbose);
        break;
    case IPPROTO_BEETPH:
        PRV1(printf("-\t\t\tBEETPH"), verbose);
        break;
    case IPPROTO_ENCAP:
        PRV1(printf("-\t\t\tENCAP"), verbose);
        break;
    case IPPROTO_PIM:
        PRV1(printf("-\t\t\tPIM"), verbose);
        break;
    case IPPROTO_COMP:
        PRV1(printf("-\t\t\tCOMP"), verbose);
        break;
    case IPPROTO_UDPLITE:
        PRV1(printf("-\t\t\tUDPLITE"), verbose);
        break;
    case IPPROTO_MPLS:
        PRV1(printf("-\t\t\tMPLS"), verbose);
        break;
    case IPPROTO_RAW:
        PRV1(printf("-\t\t\tRAW"), verbose);
        break;
    default:
        PRV1(printf("-\t\t\tIpv4"), verbose);
        break;
    }
}