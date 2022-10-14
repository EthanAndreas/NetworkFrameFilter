#include "../include/include.h"

int get_protocol_udp(const u_char *packet, struct udphdr *udp_header);

struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header);