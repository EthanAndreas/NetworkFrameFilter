#include "../include/include.h"

struct tcphdr *tcp_analyzer(const u_char *packet,
                            struct ip *ip_header);
struct udphdr *udp_analyzer(const u_char *packet,
                            struct ip *ip_header);