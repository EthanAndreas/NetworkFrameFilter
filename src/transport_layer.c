#include "../include/transport_layer.h"

struct tcphdr *tcp_analyzer(const u_char *packet,
                            struct ip *ip_header) {

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    printf("Source port : %d, Destination port : %d\n"
           "Data offset : %d, Flags :",
           ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),
           tcp_header->th_off);

    if (tcp_header->th_flags & TH_SYN)
        printf(", SYN");
    if (tcp_header->th_flags & TH_ACK)
        printf(", ACK");
    if (tcp_header->th_flags & TH_FIN)
        printf(", FIN");
    if (tcp_header->th_flags & TH_RST)
        printf(", RST");
    if (tcp_header->th_flags & TH_PUSH)
        printf(", PUSH");
    if (tcp_header->th_flags & TH_URG)
        printf(", URG");

    printf("\n");

    return tcp_header;
}

struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header) {

    struct udphdr *udp_header = (struct udphdr *)packet;

    printf("Source port : %d, Destination port : %d\n",
           ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));

    return udp_header;
}