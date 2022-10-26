#ifndef UDP
#define UDP

#include "../include/4_bootp.h"
#include "../include/4_dns.h"
#include "../include/include.h"

void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int verbose);
struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header, int verbose);

#endif