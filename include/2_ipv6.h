#ifndef IPV6
#define IPV6

#include "../include/3_tcp.h"
#include "../include/3_udp.h"
#include "../include/include.h"

struct ip6_hdr *ipv6_analyzer(const u_char *packet, int verbose);

void get_protocol_ipv6(const u_char *packet,
                       struct ip6_hdr *ipv6_header, int length,
                       int verbose);

#endif