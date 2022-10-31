#include "../include/3_tcp.h"

void get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header,
                      int verbose) {

    if (ntohs(tcp_header->th_dport) == DNS_PORT ||
        ntohs(tcp_header->th_sport) == DNS_PORT)
        dns_analyzer(packet, verbose);

    if (ntohs(tcp_header->th_dport) == BOOTP_PORT ||
        ntohs(tcp_header->th_sport) == BOOTP_PORT)
        bootp_analyzer(packet, verbose);

    int i;
    int smtp[NB_SMTP] = {SMTP_1, SMTP_2, SMTP_3, SMTP_4, SMTP_5};
    for (i = 0; i < NB_SMTP; i++) {

        if (ntohs(tcp_header->th_dport) == smtp[i] ||
            ntohs(tcp_header->th_sport) == smtp[i])
            smtp_analyzer(packet, verbose);
    }
}

struct tcphdr *tcp_analyzer(const u_char *packet, int verbose) {

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    PRV1(printf(GRN "TCP Header" NC "\n"), verbose);

    PRV1(printf("Source port : %d\n"
                "Destination port : %d\n",
                ntohs(tcp_header->th_sport),
                ntohs(tcp_header->th_dport)),
         verbose);

    PRV2(printf("Data offset : % d, Flags : ", tcp_header->th_off),
         verbose);

    int nb_flags = 0;

    if (tcp_header->th_flags & TH_SYN) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("SYN"), verbose);
        nb_flags++;
    }
    if (tcp_header->th_flags & TH_ACK) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("ACK"), verbose);
        nb_flags++;
    }
    if (tcp_header->th_flags & TH_FIN) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("FIN"), verbose);
        nb_flags++;
    }
    if (tcp_header->th_flags & TH_RST) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("RST"), verbose);
        nb_flags++;
    }
    if (tcp_header->th_flags & TH_PUSH) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("PUSH"), verbose);
        nb_flags++;
    }
    if (tcp_header->th_flags & TH_URG) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("URG"), verbose);
        nb_flags++;
    }

    if (nb_flags == 0)
        PRV2(printf("none"), verbose);
    PRV2(printf("\n"), verbose);

    return tcp_header;
}
