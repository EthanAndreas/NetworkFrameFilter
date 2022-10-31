#ifndef TCP
#define TCP

#include "../include/4_bootp.h"
#include "../include/4_dns.h"
#include "../include/4_smtp.h"
#include "../include/include.h"

void get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header,
                      int verbose);
struct tcphdr *tcp_analyzer(const u_char *packet, int verbose);

#endif