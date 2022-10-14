#ifndef BOOTP
#define BOOTP

#include "../include/include.h"

void print_dhcp_option(uint8_t bp_vend[64], int i);
void bootp_vendor_specific(uint8_t bp_vend[64]);
void bootp_analyzer(const u_char *packet);

#endif