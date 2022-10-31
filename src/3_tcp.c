#include "../include/3_tcp.h"

void get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header,
                      int verbose) {

    if (ntohs(tcp_header->th_dport) == DNS_PORT ||
        ntohs(tcp_header->th_sport) == DNS_PORT)
        dns_analyzer(packet, verbose);

    if (ntohs(tcp_header->th_dport) == BOOTP_PORT ||
        ntohs(tcp_header->th_sport) == BOOTP_PORT)
        bootp_analyzer(packet, verbose);
}

struct tcphdr *tcp_analyzer(const u_char *packet, int verbose) {

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    PRV1(printf(GRN "TCP Header" NC "\n"), verbose);

    PRV1(printf("Source port : %d, Destination port : %d\n",
                ntohs(tcp_header->th_sport),
                ntohs(tcp_header->th_dport)),
         verbose);

    PRV2(printf("Data offset : % d, Flags : ", tcp_header->th_off),
         verbose);

    if (tcp_header->th_flags & TH_SYN)
        PRV2(printf(", SYN"), verbose);
    if (tcp_header->th_flags & TH_ACK)
        PRV2(printf(", ACK"), verbose);
    if (tcp_header->th_flags & TH_FIN)
        PRV2(printf(", FIN"), verbose);
    if (tcp_header->th_flags & TH_RST)
        PRV2(printf(", RST"), verbose);
    if (tcp_header->th_flags & TH_PUSH)
        PRV2(printf(", PUSH"), verbose);
    if (tcp_header->th_flags & TH_URG)
        PRV2(printf(", URG"), verbose);

    printf("\n");

    return tcp_header;
}
