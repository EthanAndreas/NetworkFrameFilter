#ifndef ARP
#define ARP

#include "../include/1_ethernet.h"
#include "../include/include.h"

struct ether_arp *arp_analyzer(const u_char *packet, int verbose);

#endif