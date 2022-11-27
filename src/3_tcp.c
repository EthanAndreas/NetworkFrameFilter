#include "../include/3_tcp.h"

/**
 * @brief Print informations contained in TCP header and return the
 * header in a structure
 * @return struct tcphdr*
 */
struct tcphdr *tcp_analyzer(const u_char *packet, int verbose) {

    struct tcphdr *tcp_header = (struct tcphdr *)packet;

    PRV1(printf("\n" GRN "TCP Header" NC "\n"), verbose);

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
                "\t\tOptions : ",
                ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum),
                ntohs(tcp_header->th_urp)),
         verbose);
    tcp_options(packet, tcp_header->th_off, verbose);

    return tcp_header;
}

/**
 * @brief Get the protocol under TCP header
 */
void get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header,
                      int length, int verbose) {

    if (ntohs(tcp_header->th_dport) == BOOTP_PORT ||
        ntohs(tcp_header->th_sport) == BOOTP_PORT)
        bootp_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == DNS_PORT ||
        ntohs(tcp_header->th_sport) == DNS_PORT)
        dns_analyzer(packet, length, verbose);

    if ((ntohs(tcp_header->th_dport) == SMTP_PORT ||
         ntohs(tcp_header->th_sport) == SMTP_PORT) &&
        (tcp_header->th_flags & TH_ACK) &&
        (tcp_header->th_flags & TH_PUSH))
        smtp_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == HTTP_PORT ||
        ntohs(tcp_header->th_sport) == HTTP_PORT)
        http_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == HTTP2_PORT ||
        ntohs(tcp_header->th_sport) == HTTP2_PORT)
        PRV1(printf("\n" GRN "Transport Layer Security" NC "\n"),
             verbose);

    if (ntohs(tcp_header->th_dport) == FTP_PORT ||
        ntohs(tcp_header->th_sport) == FTP_PORT)
        ftp_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == POP3_PORT ||
        ntohs(tcp_header->th_sport) == POP3_PORT)
        pop3_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == IMAP_PORT ||
        ntohs(tcp_header->th_sport) == IMAP_PORT)
        imap_analyzer(packet, length, verbose);

    if (ntohs(tcp_header->th_dport) == TELNET_PORT ||
        ntohs(tcp_header->th_sport) == TELNET_PORT)
        telnet_analyzer(packet, length, verbose);
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

    int i, nb_options = 0;
    for (i = 20; i < (offset * 4); i++) {
        switch (packet[i]) {

        case TCPOPT_EOL:
            PRV3(printf("\n\t\t- End of options list"), verbose);
            nb_options++;
            break;
        case TCPOPT_NOP:
            PRV3(printf("\n\t\t- No operation"), verbose);
            break;
        case TCPOPT_MAXSEG:
            PRV3(printf("\n\t\t- Maximum segment size : %d bytes",
                        (packet[i + 2] << 8) + packet[i + 3]),
                 verbose);
            i += TCPOLEN_MAXSEG - 1;
            nb_options++;
            break;
        case TCPOPT_WINDOW:
            PRV3(printf("\n\t\t- Window scale : %d", packet[i + 2]),
                 verbose);
            i += TCPOLEN_WINDOW - 1;
            nb_options++;
            break;
        case TCPOPT_SACK_PERMITTED:
            PRV3(printf("\n\t\t- SACK permitted"), verbose);
            i += TCPOLEN_SACK_PERMITTED - 1;
            nb_options++;
            break;
        case TCPOPT_SACK:
            PRV3(printf("\n\t\t- SACK"), verbose);
            nb_options++;
            break;
        case TCPOPT_TIMESTAMP:
            PRV3(
                printf("\n\t\t- Timestamp : %u, Timestamp echo "
                       "reply : %u",
                       (packet[i + 2] << 24) + (packet[i + 3] << 16) +
                           (packet[i + 4] << 8) + packet[i + 5],
                       (packet[i + 6] << 24) + (packet[i + 7] << 16) +
                           (packet[i + 8] << 8) + packet[i + 9]),
                verbose);
            i += TCPOLEN_TIMESTAMP - 1;
            nb_options++;
            break;
        default:
            break;
        }
    }

    if (nb_options == 0)
        PRV3(printf("None\n"), verbose);
    else
        PRV3(printf("\n"), verbose);
}
