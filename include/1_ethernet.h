#ifndef ETHERNET
#define ETHERNET

#include "../include/include.h"

struct ether_header *ethernet_analyzer(const u_char *packet);
char *ether_ntoa_r(const struct ether_addr *addr, char *buf);

#endif