#include "../include/3_udp.h"

/**
 * @brief Print informations contained in UDP header and return the
 * header in a structure
 * @return struct udphdr*
 */
struct udphdr *udp_analyzer(const u_char *packet, int length,
                            int verbose) {

    struct udphdr *udp_header = (struct udphdr *)packet;

    PRV1(printf("%d -> %d\t\t", ntohs(udp_header->uh_sport),
                ntohs(udp_header->uh_dport)),
         verbose);

    if (length == sizeof(struct udphdr))
        // One line by frame
        PRV1(printf("UDP"), verbose);

    // One line from the udp header
    PRV2(printf(MAG "UDP" NC "\t\t"
                    "src port : %d, "
                    "dst port : %d, "
                    "Checksum : 0x%0x\n",
                ntohs(udp_header->uh_sport),
                ntohs(udp_header->uh_dport),
                ntohs(udp_header->uh_sum)),
         verbose);

    // Multiple lines from the udp header
    PRV3(printf("\n" GRN "UDP Header" NC "\n"
                "Source port : %d\n"
                "Destination port : %d\n"
                "Length : %d\n"
                "Checksum : 0x%02x (%d)\n",
                ntohs(udp_header->uh_sport),
                ntohs(udp_header->uh_dport),
                ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum),
                ntohs(udp_header->uh_sum)),
         verbose);

    return udp_header;
}

/**
 * @brief Get the protocol under UDP header
 */
void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int length, int verbose) {

    // Bootp + DHCP
    if (ntohs(udp_header->uh_dport) == BOOTP_PORT ||
        ntohs(udp_header->uh_sport) == BOOTP_PORT)
        bootp_analyzer(packet, length, verbose);

    // DNS
    else if (ntohs(udp_header->uh_dport) == DNS_PORT ||
             ntohs(udp_header->uh_sport) == DNS_PORT)
        dns_analyzer(packet, length, verbose);

    else
        PRV1(printf("UDP"), verbose);
}