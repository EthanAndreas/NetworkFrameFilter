#ifndef UDP
#define UDP

#include "../include/4_bootp.h"
#include "../include/4_dns.h"
#include "../include/4_ftp.h"
#include "../include/4_http.h"
#include "../include/4_smtp.h"
#include "../include/include.h"

void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int length, int verbose);
struct udphdr *udp_analyzer(const u_char *packet, int verbose);

#endif