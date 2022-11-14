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

    PRV3(printf("\t\tQuestions : %d\n"
                "\t\tAnswer RRs : %d\n"
                "\t\tAuthority RRs : %d\n",
                ntohs(dns_header->qdcount),
                ntohs(dns_header->ancount),
                ntohs(dns_header->nscount)),
         verbose);

    // - function to parse the query (execute the number of qdcount
    // times)
    //- function to parse the answer (execute the number of
    // ancount times)
    // - function to parse the authority (execute the
    // number of nscount times)
}