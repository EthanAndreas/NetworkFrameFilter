#include "../include/3_udp.h"

void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int verbose) {

    if (ntohs(udp_header->uh_dport) == DNS_PORT ||
        ntohs(udp_header->uh_sport) == DNS_PORT)
        dns_analyzer(packet, verbose);

    if (ntohs(udp_header->uh_dport) == BOOTP_PORT ||
        ntohs(udp_header->uh_sport) == BOOTP_PORT)
        bootp_analyzer(packet, verbose);
}

struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header, int verbose) {

    struct udphdr *udp_header = (struct udphdr *)packet;

    PRV1(printf("Source port : %d, Destination port : %d\n",
                ntohs(udp_header->uh_sport),
                ntohs(udp_header->uh_dport)),
         verbose);

    return udp_header;
}