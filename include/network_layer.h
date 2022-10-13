#include "../include/include.h"

struct ip *ip_analyzer(const u_char *packet);
struct ether_arp *arp_analyzer(const u_char *packet);