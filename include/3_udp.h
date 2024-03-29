#ifndef UDP
#define UDP

#include "../include/4_bootp.h"
#include "../include/4_dns.h"
#include "../include/4_ftp.h"
#include "../include/4_http.h"
#include "../include/4_imap.h"
#include "../include/4_pop3.h"
#include "../include/4_smtp.h"
#include "../include/4_telnet.h"
#include "../include/include.h"

struct udphdr *udp_analyzer(const u_char *packet, int length,
                            int verbose);

void get_protocol_udp(const u_char *packet, struct udphdr *udp_header,
                      int length, int verbose);

#endif