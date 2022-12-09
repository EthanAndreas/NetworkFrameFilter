#include "../include/4_dns.h"

/**
 * @brief Print informations contained in DNS header and print
 * queries, answers and authorities which can be found in the packet
 */
void dns_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1)
        return;

    struct dns_hdr *dns_header = (struct dns_hdr *)packet;

    // One line by frame
    PRV1(printf("DNS"), verbose);

    // One line from the dns packet
    PRV2(printf(CYN1 "DNS" NC "\t\t"), verbose);

    // Multiple lines from the dns packet
    PRV3(printf("\n" GRN "DNS Protocol" NC "\n"
                "Transaction ID : 0x%0x\n"
                "Flags : 0x%0x",
                ntohs(dns_header->id), ntohs(dns_header->flags)),
         verbose);

    if (ntohs(dns_header->flags) & 0x8000) {
        PRV2(printf("Response "), verbose);
        PRV3(printf(" (Response)\n"), verbose);
    } else {
        PRV2(printf("Query "), verbose);
        PRV3(printf(" (Query)\n"), verbose);
    }

    int qdcount = ntohs(dns_header->qdcount),
        ancount = ntohs(dns_header->ancount),
        nscount = ntohs(dns_header->nscount),
        arcount = ntohs(dns_header->arcount);

    PRV2(printf("(Nb qd : %d, Nb an : %d, Nb ns : %d)\n", qdcount,
                ancount, nscount),
         verbose);

    PRV3(printf("Questions : %d\n"
                "Answer RRs : %d\n"
                "Authority RRs : %d\n"
                "Additional RRs : %d\n",
                qdcount, ancount, nscount, arcount),
         verbose);

    int i, offset = sizeof(struct dns_hdr);

    for (i = 0; i < qdcount; i++) {

        PRV3(printf(CYN1 "Query %d" NC "\n", i + 1), verbose);
        offset = query_parsing(packet, offset, length, verbose);
    }

    for (i = 0; i < ancount; i++) {

        PRV3(printf(CYN1 "Answer %d" NC "\n", i + 1), verbose);
        offset = response_parsing(packet, offset, length, verbose);
    }

    for (i = 0; i < nscount; i++) {

        PRV3(printf(CYN1 "Authority %d" NC "\n", i + 1), verbose);
        offset = response_parsing(packet, offset, length, verbose);
    }

    for (i = 0; i < arcount; i++) {

        PRV3(printf(CYN1 "Additional %d" NC "\n", i + 1), verbose);
        offset = response_parsing(packet, offset, length, verbose);
    }
}

/**
 * @brief Print informations contained in DNS query and return the new
 * offset after reading the query
 * @return int
 */
int query_parsing(const u_char *packet, int offset, int length,
                  int verbose) {

    PRV3(printf("- Name : "), verbose);
    offset = domain_name_print(packet, offset, length, verbose);

    uint16_t type = ntohs(*(uint16_t *)(packet + offset));
    type_print(type, verbose);

    uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
    class_print(class, verbose);

    return offset + 4;
}

/**
 * @brief Print informations contained in DNS answer / authority /
 * additional and return the new offset after reading the answer
 * @return int
 */
int response_parsing(const u_char *packet, int offset, int length,
                     int verbose) {

    PRV3(printf("- Name : "), verbose);
    offset = domain_name_print(packet, offset, length, verbose);

    uint16_t type = ntohs(*(uint16_t *)(packet + offset));
    type_print(type, verbose);

    uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
    class_print(class, verbose);

    uint32_t ttl = ntohl(*(uint32_t *)(packet + offset + 4));
    PRV3(printf("- TTL : %d\n", ttl), verbose);

    uint16_t rdlength = ntohs(*(uint16_t *)(packet + offset + 8));
    PRV3(printf("- RD Length : %d\n", rdlength), verbose);

    data_reader(type, packet, offset + 10, offset + 10 + rdlength,
                length, verbose);

    return offset + 10 + rdlength;
}

/**
 * @brief Print data blocks contained in answers or authorities. Data
 * blocks is differentiated by answer and authority type, and print
 * informations in function of this type
 */
void data_reader(uint16_t type, const u_char *packet, int i,
                 uint16_t rdlength, int length, int verbose) {

    int j;

    switch (type) {

    case 1:
        PRV3(printf("- IPv4 Address : "), verbose);
        for (j = 0; j < 4; j++) {
            PRV3(printf("%d", packet[i + j]), verbose);
            if (j != 3)
                PRV3(printf("."), verbose);
        }
        PRV3(printf("\n"), verbose);
        break;

    case 2:
        PRV3(printf("- Name Server : "), verbose);
        domain_name_print(packet, i, length, verbose);
        break;

    case 5:
        PRV3(printf("- Canonical Name : "), verbose);
        domain_name_print(packet, i, length, verbose);
        break;

    case 6:
        PRV3(printf("- Primary Name Server : "), verbose);
        i = name_print(packet, i, length, verbose);

        PRV3(printf("- Responsible Authority's Mailbox : "), verbose);
        i = name_print(packet, i, length, verbose);

        uint32_t serial_nb = ntohl(*(uint32_t *)(packet + i));
        PRV3(printf("- Serial Number : %d\n", serial_nb), verbose);

        uint32_t refresh = ntohl(*(uint32_t *)(packet + i + 4));
        PRV3(printf("- Refresh : %d\n", refresh), verbose);

        uint32_t retry = ntohl(*(uint32_t *)(packet + i + 8));
        PRV3(printf("- Retry : %d\n", retry), verbose);

        uint32_t expire = ntohl(*(uint32_t *)(packet + i + 12));
        PRV3(printf("- Expire : %d\n", expire), verbose);

        uint32_t minimum = ntohl(*(uint32_t *)(packet + i + 16));
        PRV3(printf("- Minimum : %d\n", minimum), verbose);
        break;

    case 12:
        PRV3(printf("- Pointer : "), verbose);
        domain_name_print(packet, i, length, verbose);
        break;

    case 15:
        PRV3(printf("- Mail Exchange : "), verbose);
        domain_name_print(packet, i + 2, length, verbose);
        break;

    case 16:
        PRV3(printf("- Text : "), verbose);
        for (j = 0; j < packet[i]; j++) {
            PRV3(printf("%c", packet[i + j + 1]), verbose);
        }
        PRV3(printf("\n"), verbose);
        break;

    case 28:
        PRV3(printf("- IPv6 Address : "), verbose);
        for (j = 0; j < 16; j++) {
            PRV3(printf("%x", packet[i + j]), verbose);
            if (j != 15) {
                PRV3(printf(":"), verbose);
            }
        }
        PRV3(printf("\n"), verbose);
        break;

    default:
        break;
    }
}

/**
 * @brief Print domain name contained in queries, answers and
 * authorities
 */
int domain_name_print(const u_char *packet, int i, int length,
                      int verbose) {

    int j, start = i;
    while (packet[i] != 0 && i < length) {

        if (packet[i] == 0xc0) {
            if (i != start)
                PRV3(printf("."), verbose);
            domain_name_print(packet, packet[i + 1], length, verbose);
            return i + 2;
        }

        if (packet[i] != 0 && i != start)
            PRV3(printf("."), verbose);

        for (j = 0; j < packet[i]; j++)
            PRV3(printf("%c", packet[i + j + 1]), verbose);

        i += packet[i] + 1;
    }

    PRV3(printf("\n"), verbose);
    return i + 1;
}

/**
 * @brief Print name contained in SOA records
 */
int name_print(const u_char *packet, int i, int length, int verbose) {

    int j, position;

    if (packet[i] == 0xc0)
        j = packet[i + 1];
    else
        j = i;

    position = j;
    while (j < packet[position] + position && j < length) {
        j++;

        if (packet[j] == 0xc0) {
            name_print(packet, j, length, verbose);
            j += 2;
        }

        PRV3(printf("%c", packet[j]), verbose);
    }

    PRV3(printf("\n"), verbose);

    if (packet[i] == 0xc0)
        return i + 2;
    else
        return i + packet[i] + 2;
}

/**
 * @brief Print type of queries, answers and authorities
 */
void type_print(u_int16_t type, int verbose) {

    PRV3(printf("- Type : "), verbose);

    switch (type) {
    case 1:
        PRV3(printf("A (Host Address)\n"), verbose);
        break;
    case 2:
        PRV3(printf("NS (Authoritative Name Server)\n"), verbose);
        break;
    case 5:
        PRV3(printf("CNAME (Canonical Name)\n"), verbose);
        break;
    case 6:
        PRV3(printf("SOA (Start of Authority)\n"), verbose);
        break;
    case 12:
        PRV3(printf("PTR (Domain Name Pointer)\n"), verbose);
        break;
    case 15:
        PRV3(printf("MX (Mail Exchange)\n"), verbose);
        break;
    case 16:
        PRV3(printf("TXT (Text Strings)\n"), verbose);
        break;
    case 28:
        PRV3(printf("AAAA (IPv6 Address)\n"), verbose);
        break;
    case 251:
        PRV3(printf("IXFR (Incremental Zone Transfer)\n"), verbose);
        break;
    default:
        PRV3(printf("Unknown\n"), verbose);
        break;
    }
}

/**
 * @brief Print class of queries, answers and authorities
 */
void class_print(u_int16_t class, int verbose) {

    PRV3(printf("- Class : "), verbose);

    switch (class) {
    case 1:
        PRV3(printf("IN (Internet)\n"), verbose);
        break;
    case 2:
        PRV3(printf("CS (CSNET)\n"), verbose);
        break;
    case 3:
        PRV3(printf("CH (Chaos)\n"), verbose);
        break;
    case 4:
        PRV3(printf("HS (Hesiod)\n"), verbose);
        break;
    default:
        PRV3(printf("Unknown\n"), verbose);
        break;
    }
}
