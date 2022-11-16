#include "../include/4_dns.h"

void dns_analyzer(const u_char *packet, int length, int verbose) {

    PRV1(printf(GRN "DNS Protocol" NC "\n"), verbose);

    struct dns_hdr *dns_header = (struct dns_hdr *)packet;
    packet += sizeof(struct dns_hdr);

    PRV2(printf("\tTransaction ID : 0x%0x\n", ntohs(dns_header->id)),
         verbose);

    PRV2(printf("\tFlags : 0x%0x", ntohs(dns_header->flags)),
         verbose);
    if (ntohs(dns_header->flags) & 0x8000) {
        PRV2(printf(" (Response)\n"), verbose);
    } else {
        PRV2(printf(" (Query)\n"), verbose);
    }

    int qdcount = ntohs(dns_header->qdcount);
    int ancount = ntohs(dns_header->ancount);
    int nscount = ntohs(dns_header->nscount);

    PRV3(printf("\t\tQuestions : %d\n"
                "\t\tAnswer RRs : %d\n"
                "\t\tAuthority RRs : %d\n",
                qdcount, ancount, nscount),
         verbose);

    int i;

    struct query_t *queries =
        malloc(ntohs(dns_header->qdcount) * sizeof(struct query_t));
    for (i = 0; i < qdcount; i++) {

        PRV3(printf("\t\tQuery %d\n", i + 1), verbose);
        queries[i] = query_parsing(packet, length, verbose);
    }

    struct answer_t *answers =
        malloc(ntohs(dns_header->ancount) * sizeof(struct answer_t));
    for (i = 0; i < ancount; i++) {

        PRV3(printf("\t\tAnswer %d\n", i + 1), verbose);
        answers[i] = answer_parsing(packet, length, verbose);
    }

    struct authority_t *authorities = malloc(
        ntohs(dns_header->nscount) * sizeof(struct authority_t));
    for (i = 0; i < nscount; i++) {

        PRV3(printf("\t\tAuthority %d\n", i + 1), verbose);
        authorities[i] = authority_parsing(packet, length, verbose);
    }
}

struct query_t query_parsing(const u_char *packet, int length,
                             int verbose) {

    struct query_t query;

    struct dns_name_t domain = name_reader(packet, length);
    strcpy(query.qname, domain.name);
    query.length = domain.length;
    packet += query.length;

    query.qtype = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    query.qclass = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    PRV3(printf("\t\t- Name : %s\n", query.qname), verbose);

    PRV3(printf("\t\t- Type : "), verbose);
    type_print(query.qtype, verbose);

    PRV3(printf("\t\t- Class : "), verbose);
    class_print(query.qclass, verbose);

    return query;
}

struct answer_t answer_parsing(const u_char *packet, int length,
                               int verbose) {

    struct answer_t answer;

    struct dns_name_t domain = name_reader(packet, length);
    strcpy(answer.name, domain.name);
    answer.length = domain.length;
    packet += answer.length;

    answer.type = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    answer.class = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    answer.ttl = ntohl(*(u_int32_t *)packet);
    packet += sizeof(u_int32_t);

    answer.rdlength = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    answer.rdata = malloc(answer.rdlength);
    memcpy(answer.rdata, packet, answer.rdlength);
    packet += answer.rdlength;

    PRV3(printf("\t\t- Name : %s\n", answer.name), verbose);

    PRV3(printf("\t\t- Type : "), verbose);
    type_print(answer.type, verbose);

    PRV3(printf("\t\t- Class : "), verbose);
    class_print(answer.class, verbose);

    PRV3(printf("\t\t- TTL : %d\n", answer.ttl), verbose);

    PRV3(printf("\t\t- RD Length : %d\n", answer.rdlength), verbose);

    PRV3(printf("\t\t- RData : "), verbose);
    rdata_print(answer.type, answer.rdata, answer.rdlength, verbose);

    return answer;
}

struct authority_t authority_parsing(const u_char *packet, int length,
                                     int verbose) {

    struct authority_t authority;

    struct dns_name_t domain = name_reader(packet, length);
    strcpy(authority.name, domain.name);
    authority.length = domain.length;
    packet += authority.length;

    authority.type = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    authority.class = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    authority.ttl = ntohl(*(u_int32_t *)packet);
    packet += sizeof(u_int32_t);

    authority.rdlength = ntohs(*(u_int16_t *)packet);
    packet += sizeof(u_int16_t);

    authority.rdata = malloc(authority.rdlength);
    memcpy(authority.rdata, packet, authority.rdlength);
    packet += authority.rdlength;

    PRV3(printf("\t\t- Name : %s\n", authority.name), verbose);

    PRV3(printf("\t\t- Type : "), verbose);
    type_print(authority.type, verbose);

    PRV3(printf("\t\t- Class : "), verbose);
    class_print(authority.class, verbose);

    PRV3(printf("\t\t- TTL : %d\n", authority.ttl), verbose);

    PRV3(printf("\t\t- RD Length : %d\n", authority.rdlength),
         verbose);

    PRV3(printf("\t\t- RData : "), verbose);
    rdata_print(authority.type, authority.rdata, authority.rdlength,
                verbose);

    return authority;
}

struct dns_name_t name_reader(const u_char *packet, int length) {

    struct dns_name_t domain;

    int i = 0;
    int block_length = packet[i];

    while (packet[i] != 0x00 && i < length) {

        if (i == block_length + 1) {
            domain.name[i] = '.';
            block_length = packet[i];
        } else
            domain.name[i] = packet[i];
        i++;
    }

    domain.name[i] = '\0';
    domain.length = i + 1;

    return domain;
}

void type_print(u_int16_t type, int verbose) {

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

void rdata_print(u_int16_t type, u_char *rdata, u_int16_t rdlength,
                 int verbose) {

    switch (type) {
    case 1:
        PRV3(printf("%d.%d.%d.%d\n", rdata[0], rdata[1], rdata[2],
                    rdata[3]),
             verbose);
        break;
    case 2:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    case 5:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    case 6:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    case 12:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    case 15:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    case 16:
        PRV3(printf("%s\n", rdata), verbose);
        break;
    default:
        PRV3(printf("Unknown\n"), verbose);
        break;
    }
}