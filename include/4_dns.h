#ifndef DNS
#define DNS

#include "../include/include.h"

struct dns_hdr {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

void dns_analyzer(const u_char *packet, int lenght, int verbose);

#endif