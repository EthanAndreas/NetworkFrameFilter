#include "../include/4_bootp.h"

void bootp_vendor_specific(struct bootp *bootp_header) {}

void bootp_analyzer(const u_char *packet) {

    struct bootp *bootp_header = (struct bootp *)packet;

    if (bootp_header->bp_op == BOOTREQUEST)
        printf("Op : Request, \n");
    else if (bootp_header->bp_op == BOOTREPLY)
        printf("Op : Reply\n");
}
