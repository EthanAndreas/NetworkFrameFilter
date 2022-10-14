#include "../include/4_bootp.h"

void print_dhcp_option(uint8_t bp_vend[64], int i) {

    int j;
    for (j = 1; j <= bp_vend[i + 1]; j++) {
        if (j != 1 && j != bp_vend[i + 1])
            printf(".");
        printf("%d", bp_vend[i + j + 1]);
    }
}

void bootp_vendor_specific(uint8_t bp_vend[64]) {

    if (bp_vend[0] == 0x63 && bp_vend[1] == 0x82 &&
        bp_vend[2] == 0x53 && bp_vend[3] == 0x63) {
        printf("DHCP protocol, ");
    }

    int i, j;
    for (i = 0; i < 64; i++) {

        switch (bp_vend[i]) {

        case TAG_SUBNET_MASK:

            printf("Subnet mask : ");
            print_dhcp_option(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            printf("Time offset : %d, ", bp_vend[i + 1]);
            i += 5;
            break;

        // DCHP options
        case TAG_DHCP_MESSAGE:
            printf("DHCP options : ");
            for (j = 1; j <= bp_vend[i + 1]; j++) {
                switch (bp_vend[i + 1 + j]) {
                case DHCPDISCOVER:
                    printf("Discover\n");
                    break;
                case DHCPOFFER:
                    printf("Offer\n");
                    break;
                case DHCPREQUEST:
                    printf("Request\n");
                    break;
                case DHCPDECLINE:
                    printf("Decline\n");
                    break;
                case DHCPACK:
                    printf("Ack\n");
                    break;
                case DHCPNAK:
                    printf("Nack\n");
                    break;
                case DHCPRELEASE:
                    printf("Release\n");
                    break;
                case DHCPINFORM:
                    printf("Inform\n");
                    break;
                default:
                    break;
                }
            }

            i += bp_vend[i + 1] + 1;
            break;
        default:
            break;
        }
    }
}

void bootp_analyzer(const u_char *packet) {

    struct bootp *bootp_header = (struct bootp *)packet;

    if (bootp_header->bp_op == BOOTREQUEST)
        printf("Request, ");
    else if (bootp_header->bp_op == BOOTREPLY)
        printf("Reply, ");

    if (bootp_header->bp_htype == HTYPE_ETHER)
        printf("Ethernet, ");

    bootp_vendor_specific(bootp_header->bp_vend);
}
