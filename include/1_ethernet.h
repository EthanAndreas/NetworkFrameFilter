#ifndef ETHERNET
#define ETHERNET

#include "../include/include.h"

char *addr_mac_print(const struct ether_addr *addr, char *buf);

struct ether_header *ethernet_analyzer(const u_char *packet,
                                       int verbose);

#endif