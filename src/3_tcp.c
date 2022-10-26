#include "../include/3_tcp.h"

void get_protocol_tcp(const u_char *packet,
                      struct tcphdr *tcp_header) {

    if (ntohs(tcp_header->th_dport) == DNS_PORT ||
        ntohs(tcp_header->th_sport) == DNS_PORT)
        dns_analyzer(packet);

    if (ntohs(tcp_header->th_dport) == BOOTP_PORT ||
        ntohs(tcp_header->th_sport) == BOOTP_PORT)
        bootp_analyzer(packet, 1);
}

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
