#ifndef TCP
#define TCP

#include "../include/4_bootp.h"
#include "../include/4_dns.h"
#include "../include/4_ftp.h"
#include "../include/4_http.h"
#include "../include/4_smtp.h"
#include "../include/include.h"

void get_protocol_tcp(const u_char *packet, struct tcphdr *tcp_header,
                      int verbose);
struct tcphdr *tcp_analyzer(const u_char *packet, int verbose);

void tcp_flags(uint8_t flags, int verbose);

void tcp_options(const u_char *packet, uint8_t offset, int verbose);

#endif