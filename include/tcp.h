#include "../include/include.h"

int get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header);
struct tcphdr *tcp_analyzer(const u_char *packet,
                            struct ip *ip_header);