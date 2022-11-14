#ifndef BOOTP
#define BOOTP

#include "../include/include.h"

void bootp_analyzer(const u_char *packet, int length, int verbose);
void print_dhcp_option_addr(const u_char *bp_vend, int i, int length);
void print_dhcp_option_name(const u_char *bp_vend, int i, int length);
void print_dhcp_option_int(const u_char *bp_vend, int i, int length);
void bootp_vendor_specific(const u_char *bp_vend, int length,
                           int verbose);

#endif