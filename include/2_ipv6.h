#ifndef IPV6
#define IPV6

#include "../include/include.h"

struct ip6_hdr *ipv6_analyzer(const u_char *packet, int verbose);

#endif