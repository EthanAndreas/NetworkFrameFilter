#ifndef ARP
#define ARP

#include "../include/include.h"

struct ether_arp *arp_analyzer(const u_char *packet);

#endif