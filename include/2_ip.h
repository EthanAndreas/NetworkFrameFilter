#ifndef IP
#define IP

#include "../include/include.h"

struct iphdr *ip_analyzer(const u_char *packet, int verbose);

#endif