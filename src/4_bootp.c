#include "../include/4_bootp.h"

void print_dhcp_option_addr(uint8_t bp_vend[64], int i) {

    int j;
    for (j = 1; j <= bp_vend[i + 1]; j++) {
        if (j != 1 && j != bp_vend[i + 1] + 1)
            printf(".");
        printf("%d", bp_vend[i + j + 1]);
    }
    printf("\n");
}

void print_dhcp_option_name(uint8_t bp_vend[64], int i) {

    int j;
    for (j = 1; j <= bp_vend[i + 1]; j++) {
        printf("%c", bp_vend[i + j + 1]);
    }
    printf("\n");
}

void print_dhcp_option_time(uint8_t bp_vend[64], int i) {

    uint32_t time = 0;
    time += bp_vend[i + 2] << 24;
    time += bp_vend[i + 3] << 16;
    time += bp_vend[i + 4] << 8;
    time += bp_vend[i + 5];
    printf("%d\n", time);
}

void bootp_vendor_specific(uint8_t bp_vend[64]) {

    if (bp_vend[0] == 0x63 && bp_vend[1] == 0x82 &&
        bp_vend[2] == 0x53 && bp_vend[3] == 0x63) {
        printf("DHCP protocol\n");
    }

    int i, j;
    for (i = 0; i < 64; i++) {

        switch (bp_vend[i]) {

        case TAG_SUBNET_MASK:

            printf("Subnet mask : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            printf("Time offset : ");
            print_dhcp_option_time(bp_vend, i);
            i += 5;
            break;
        case TAG_GATEWAY:
            printf("Router : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAIN_SERVER:
            printf("DNS : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_HOSTNAME:
            printf("Hostname : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAINNAME:
            printf("Domain name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BROAD_ADDR:
            printf("Broadcast : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NS:
            printf("Netbios name server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_SCOPE:
            printf("Netbios scope : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REQUESTED_IP:
            printf("Requested IP address : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IP_LEASE:
            printf("Lease time : ");
            print_dhcp_option_time(bp_vend, i);
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
        case TAG_SERVER_ID:
            printf("DHCP server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PARM_REQUEST:
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
