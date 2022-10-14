#include "../include/udp.h"

int get_protocol_udp(const u_char *packet,
                     struct udphdr *udp_header) {

    if (ntohs(udp_header->uh_dport) == DNS_PORT ||
        ntohs(udp_header->uh_sport) == DNS_PORT)
        return DNS_PORT;

    if (ntohs(udp_header->uh_dport) == BOOTP_PORT ||
        ntohs(udp_header->uh_sport) == BOOTP_PORT)
        return BOOTP_PORT;

    return 0;
}

struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header) {

    struct udphdr *udp_header = (struct udphdr *)packet;

    printf("Source port : %d, Destination port : %d\n",
           ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));

    return udp_header;
}