#ifndef BOOTP
#define BOOTP

#include "../include/include.h"

void bootp_vendor_specific(struct bootp *bootp_header);
void bootp_analyzer(const u_char *packet);

#endif