#include "../include/4_dns.h"

void dns_analyzer(const u_char *packet, int length, int verbose) {

    PRV1(printf(GRN "DNS Protocol" NC "\n"), verbose);

    struct dns_hdr *dns_header = (struct dns_hdr *)packet;

    PRV2(printf("\tTransaction ID : 0x%0x\n", ntohs(dns_header->id)),
         verbose);

    PRV2(printf("\tFlags : 0x%0x", ntohs(dns_header->flags)),
         verbose);
    if (ntohs(dns_header->flags) & 0x8000) {
        PRV2(printf(" (Response)\n"), verbose);
    } else {
        PRV2(printf(" (Query)\n"), verbose);
    }

    int qdcount = ntohs(dns_header->qdcount),
        ancount = ntohs(dns_header->ancount),
        nscount = ntohs(dns_header->nscount);

    PRV3(printf("\t\tQuestions : %d\n"
                "\t\tAnswer RRs : %d\n"
                "\t\tAuthority RRs : %d\n",
                qdcount, ancount, nscount),
         verbose);

    int i, offset = sizeof(struct dns_hdr);

    for (i = 0; i < qdcount; i++) {

        PRV3(printf("\t\tQuery %d\n", i + 1), verbose);
        offset = query_parsing(packet, offset, length, verbose);
    }

    for (i = 0; i < ancount; i++) {

        PRV3(printf("\t\tAnswer %d\n", i + 1), verbose);
        offset = answer_parsing(packet, offset, length, verbose);
    }

    for (i = 0; i < nscount; i++) {

        PRV3(printf("\t\tAuthority %d\n", i + 1), verbose);
        offset = authority_parsing(packet, offset, length, verbose);
    }
}

int query_parsing(const u_char *packet, int offset, int length,
                  int verbose) {

    PRV3(printf("\t\t- Name : "), verbose);
    offset = name_reader(packet, offset, length, verbose);

    uint16_t type = ntohs(*(uint16_t *)(packet + offset));
    type_print(type, verbose);

    uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
    class_print(class, verbose);

    return offset + 4;
}

int answer_parsing(const u_char *packet, int offset, int length,
                   int verbose) {

    PRV3(printf("\t\t- Name : "), verbose);
    offset = name_reader(packet, offset, length, verbose);

    uint16_t type = ntohs(*(uint16_t *)(packet + offset));
    type_print(type, verbose);

    uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
    class_print(class, verbose);

    uint32_t ttl = ntohl(*(uint32_t *)(packet + offset + 4));
    PRV3(printf("\t\t- TTL : %d\n", ttl), verbose);

    uint16_t rdlength = ntohs(*(uint16_t *)(packet + offset + 8));
    PRV3(printf("\t\t- RD Length : %d\n", rdlength), verbose);

    PRV3(printf("\t\t- RData :\n"), verbose);
    data_reader(packet, offset + 10, offset + 10 + rdlength, length,
                verbose);

    return offset + 10 + rdlength;
}

int authority_parsing(const u_char *packet, int offset, int length,
                      int verbose) {

    PRV3(printf("\t\t- Name : "), verbose);
    offset = name_reader(packet, offset, length, verbose);

    uint16_t type = ntohs(*(uint16_t *)(packet + offset));
    type_print(type, verbose);

    uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
    class_print(class, verbose);

    uint32_t ttl = ntohl(*(uint32_t *)(packet + offset + 4));
    PRV3(printf("\t\t- TTL : %d\n", ttl), verbose);

    uint16_t rdlength = ntohs(*(uint16_t *)(packet + offset + 8));
    PRV3(printf("\t\t- RD Length : %d\n", rdlength), verbose);

    PRV3(printf("\t\t- RData :\n"), verbose);
    data_reader(packet, offset + 10, offset + 10 + rdlength, length,
                verbose);

    return offset + 10 + rdlength;
}

int name_reader(const u_char *packet, int i, int length,
                int verbose) {

    int j;
    while (packet[i] != 0 && i < length) {

        if (packet[i] == 0xc0) {
            name_reader(packet, packet[i + 1], length, verbose);
            return i + 2;
        }

        for (j = 0; j < packet[i]; j++) {
            PRV3(printf("%c", packet[i + j + 1]), verbose);
        }

        PRV3(printf("."), verbose);
        i += packet[i] + 1;
    }

    PRV3(printf("\n"), verbose);
    return i + 1;
}

void data_reader(const u_char *packet, int i, uint16_t rdlength,
                 int length, int verbose) {

    int j, position;
    while (i < rdlength - 20) {

        if (packet[i] == 0xc0) {

            PRV3(printf("\t\t\t"), verbose);
            position = packet[i + 1];
            for (j = 0; j < packet[position]; j++)
                PRV3(printf("%c", packet[position + j + 1]), verbose);
            // recursive call but dots appears
            // name_reader(packet, position, length, verbose);
            i += 2;
        } else {

            PRV3(printf("\t\t\t"), verbose);
            for (j = 0; j < packet[i]; j++)
                PRV3(printf("%c", packet[i + j + 1]), verbose);
            i += packet[i] + 2;
        }

        PRV3(printf("\n"), verbose);
    }

    uint32_t serial_nb = ntohl(*(uint32_t *)(packet + i));
    PRV3(printf("\t\t\tSerial Number : %d\n", serial_nb), verbose);

    uint32_t refresh = ntohl(*(uint32_t *)(packet + i + 4));
    PRV3(printf("\t\t\tRefresh : %d\n", refresh), verbose);

    uint32_t retry = ntohl(*(uint32_t *)(packet + i + 8));
    PRV3(printf("\t\t\tRetry : %d\n", retry), verbose);

    uint32_t expire = ntohl(*(uint32_t *)(packet + i + 12));
    PRV3(printf("\t\t\tExpire : %d\n", expire), verbose);

    uint32_t minimum = ntohl(*(uint32_t *)(packet + i + 16));
    PRV3(printf("\t\t\tMinimum : %d\n", minimum), verbose);
}

void type_print(u_int16_t type, int verbose) {

    PRV3(printf("\t\t- Type : "), verbose);

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

void class_print(u_int16_t class, int verbose) {

    PRV3(printf("\t\t- Class : "), verbose);

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
