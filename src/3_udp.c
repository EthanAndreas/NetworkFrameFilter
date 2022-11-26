#include "../include/3_udp.h"

void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int length, int verbose) {

    if (ntohs(udp_header->uh_dport) == DNS_PORT ||
        ntohs(udp_header->uh_sport) == DNS_PORT)
        dns_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == BOOTP_PORT ||
        ntohs(udp_header->uh_sport) == BOOTP_PORT)
        bootp_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == HTTP_PORT ||
        ntohs(udp_header->uh_sport) == HTTP_PORT)
        http_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == HTTP2_PORT ||
        ntohs(udp_header->uh_sport) == HTTP2_PORT)
        http_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == FTP_PORT ||
        ntohs(udp_header->uh_sport) == FTP_PORT)
        ftp_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == IMAP_PORT ||
        ntohs(udp_header->uh_sport) == IMAP_PORT)
        imap_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == POP3_PORT ||
        ntohs(udp_header->uh_sport) == POP3_PORT)
        pop3_analyzer(packet, length, verbose);

    if (ntohs(udp_header->uh_dport) == TELNET_PORT ||
        ntohs(udp_header->uh_sport) == TELNET_PORT)
        telnet_analyzer(packet, length, verbose);
}

struct udphdr *udp_analyzer(const u_char *packet, int verbose) {

    struct udphdr *udp_header = (struct udphdr *)packet;

    PRV1(printf(GRN "UDP Header" NC "\n"), verbose);

    PRV1(printf("Source port : %d\n"
                "Destination port : %d\n",
                ntohs(udp_header->uh_sport),
                ntohs(udp_header->uh_dport)),
         verbose);

    PRV2(printf("\tLength : %d\n"
                "\tChecksum : 0x%02x (%d)\n",
                ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum),
                ntohs(udp_header->uh_sum)),
         verbose);

    return udp_header;
}