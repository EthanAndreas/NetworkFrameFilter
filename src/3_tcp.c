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

    PRV2(printf("\tSequence number : %u\n"
                "\tAcknowledgment number : %u\n"
                "\tData offset : %d bits (%d)\n"
                "\tFlags : ",
                ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack),
                tcp_header->th_off * 4, tcp_header->th_off),
         verbose);
    tcp_flags(tcp_header->th_flags, verbose);

    PRV3(printf("\t\tWindow size : %d\n"
                "\t\tChecksum : 0x%0x\n"
                "\t\tUrgent pointer : %d\n"
                "\t\tOptions :\n",
                ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum),
                ntohs(tcp_header->th_urp)),
         verbose);
    tcp_options(packet, tcp_header->th_off, verbose);

    return tcp_header;
}

/**
 * @brief Print TCP flags at level of verbose 2
 */
void tcp_flags(uint8_t flags, int verbose) {

    int nb_flags = 0;

    if (flags & TH_SYN) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("SYN"), verbose);
        nb_flags++;
    }
    if (flags & TH_ACK) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("ACK"), verbose);
        nb_flags++;
    }
    if (flags & TH_FIN) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("FIN"), verbose);
        nb_flags++;
    }
    if (flags & TH_RST) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("RST"), verbose);
        nb_flags++;
    }
    if (flags & TH_PUSH) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("PUSH"), verbose);
        nb_flags++;
    }
    if (flags & TH_URG) {
        if (nb_flags != 0)
            PRV2(printf(", "), verbose);
        PRV2(printf("URG"), verbose);
        nb_flags++;
    }

    if (nb_flags == 0)
        PRV2(printf("none"), verbose);
    PRV2(printf("\n"), verbose);
}

/**
 * @brief Print TCP options at level of verbose 3
 */
void tcp_options(const u_char *packet, uint8_t offset, int verbose) {

    if (offset < 5)
        return;

    int i;
    for (i = 20; i < (offset * 4); i++) {
        switch (packet[i]) {

        case TCPOPT_EOL:
            PRV3(printf("\t\t- End of options list\n"), verbose);
            break;

        case TCPOPT_NOP:
            PRV3(printf("\t\t- No operation\n"), verbose);
            break;

        case TCPOPT_MAXSEG:
            PRV3(printf("\t\t- Maximum segment size : %d bytes\n",
                        (packet[i + 2] << 8) + packet[i + 3]),
                 verbose);
            i += TCPOLEN_MAXSEG - 1;
            break;

        case TCPOPT_WINDOW:
            PRV3(printf("\t\t- Window scale : %d\n", packet[i + 2]),
                 verbose);
            i += TCPOLEN_WINDOW - 1;
            break;

        case TCPOPT_SACK_PERMITTED:
            PRV3(printf("\t\t- SACK permitted\n"), verbose);
            i += TCPOLEN_SACK_PERMITTED - 1;
            break;

        case TCPOPT_SACK:
            PRV3(printf("\t\t- SACK"), verbose);
            break;

        case TCPOPT_TIMESTAMP:
            PRV3(
                printf("\t\t- Timestamp : %u, Timestamp echo "
                       "reply : %u\n",
                       (packet[i + 2] << 24) + (packet[i + 3] << 16) +
                           (packet[i + 4] << 8) + packet[i + 5],
                       (packet[i + 6] << 24) + (packet[i + 7] << 16) +
                           (packet[i + 8] << 8) + packet[i + 9]),
                verbose);
            i += TCPOLEN_TIMESTAMP - 1;
            break;

        default:
            PRV3(printf("\t\t- Unknown option : %d\n", packet[i]),
                 verbose);
            break;
        }
    }
}
