#include "../include/include.h"
#include "../include/netinet_bootp.h"

void bootp_vendor_specific(struct bootp *bootp_header);
void bootp_analyzer(const u_char *packet);