#ifndef BOOTP
#define BOOTP

#include "../include/include.h"

void bootp_analyzer(const u_char *packet);
void print_dhcp_option_addr(uint8_t bp_vend[64], int i);
void print_dhcp_option_name(uint8_t bp_vend[64], int i);
void print_dhcp_option_int(uint8_t bp_vend[64], int i);
void bootp_vendor_specific(uint8_t bp_vend[64]);

#endif