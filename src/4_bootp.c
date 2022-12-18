#include "../include/4_bootp.h"

/**
 * @brief Print informations contained in BOOTP header
 */
void bootp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0) {
        PRV1(printf("UDP"), verbose);
        return;
    }

    struct bootp *bootp_header = (struct bootp *)packet;

    if (bootp_header->bp_vend[0] == 0x63 &&
        bootp_header->bp_vend[1] == 0x82 &&
        bootp_header->bp_vend[2] == 0x53 &&
        bootp_header->bp_vend[3] == 0x63)
        // One line by frame
        PRV1(printf("DHCP"), verbose);
    else
        // One line by frame
        PRV1(printf("BOOTP"), verbose);

    // One line from the bootp packet
    PRV2(printf(CYN1 "Bootp" NC "\t\t"), verbose);

    // Multiple lines from the bootp packet
    PRV3(printf("\n" GRN "Bootp protocol" NC "\n"), verbose);

    PRV3(printf("Message type : "), verbose);
    if (bootp_header->bp_op == BOOTREQUEST) {
        PRV2(printf("Request, "), verbose);
        PRV3(printf("Request"), verbose);
    } else if (bootp_header->bp_op == BOOTREPLY) {
        PRV2(printf("Reply, "), verbose);
        PRV3(printf("Reply"), verbose);
    }
    PRV3(printf("\n"), verbose);

    if (bootp_header->bp_htype == HTYPE_ETHER)
        PRV3(printf("Hardware type : Ethernet\n"), verbose);

    PRV3(printf("Flags : "), verbose);
    if (bootp_header->bp_flags == BOOTPUNICAST) {
        PRV2(printf("Unicast, "), verbose);
        PRV3(printf("Unicast (0x%02x)", bootp_header->bp_flags),
             verbose);
    } else if (ntohs(bootp_header->bp_flags) & BOOTPBROADCAST) {
        PRV2(printf("Broadcast, "), verbose);
        PRV3(printf("Broadcast (0x%02x)", bootp_header->bp_flags),
             verbose);
    }
    PRV3(printf("\n"), verbose);

    PRV2(printf("Transaction ID : %02x:%02x:%02x:%02x\n",
                bootp_header->bp_xid[0], bootp_header->bp_xid[1],
                bootp_header->bp_xid[2], bootp_header->bp_xid[3]),
         verbose);

    PRV3(printf("Transaction ID : %02x:%02x:%02x:%02x\n",
                bootp_header->bp_xid[0], bootp_header->bp_xid[1],
                bootp_header->bp_xid[2], bootp_header->bp_xid[3]),
         verbose);

    PRV3(printf("Client IP address : %s\n",
                inet_ntoa(bootp_header->bp_ciaddr)),
         verbose);

    PRV3(printf("Your IP address : %s\n",
                inet_ntoa(bootp_header->bp_yiaddr)),
         verbose);

    PRV3(printf("Server IP address : %s\n",
                inet_ntoa(bootp_header->bp_siaddr)),
         verbose);

    PRV3(printf("Gateway IP address : %s\n",
                inet_ntoa(bootp_header->bp_giaddr)),
         verbose);

    PRV3(printf("Client hardware address : %s\n",
                ether_ntoa(
                    (struct ether_addr *)bootp_header->bp_chaddr)),
         verbose);

    PRV3(printf("Hardware address length : %d\n"
                "Hops : %d\n"
                "Seconds since boot began : %d\n",
                bootp_header->bp_hlen, bootp_header->bp_hops,
                bootp_header->bp_secs),
         verbose);

    if (bootp_header->bp_sname[0] == '\0')
        PRV3(printf("Server host name : not given\n"), verbose);
    else
        PRV3(
            printf("Server host name : %s\n", bootp_header->bp_sname),
            verbose);

    if (bootp_header->bp_file[0] == '\0')
        PRV3(printf("Boot file name : not given\n"), verbose);
    else
        PRV3(printf("Boot file name : %s\n", bootp_header->bp_file),
             verbose);

    // Vendor is a variable length field
    const u_char *bp_vend = bootp_header->bp_vend;

    bootp_vendor_specific(
        bp_vend, length - sizeof(struct bootp *) + 64, verbose);
}

/**
 * @brief Used for print IP address in the vendor specific print's
 * function
 */
void print_dhcp_option_addr(const u_char *bp_vend, int i,
                            int length) {

    if (i + 1 > length || i + bp_vend[i + 1] > length)
        return;

    int j;
    for (j = 1; j <= bp_vend[i + 1]; j++) {
        if ((j != 1 && j != bp_vend[i + 1] + 1) && j % 4 != 1)
            printf(".");

        printf("%d", bp_vend[i + j + 1]);

        if (j % 4 == 0 && j != bp_vend[i + 1])
            printf(" ");
    }
    printf("\n");
}

/**
 * @brief Used for print name in the vendor specific print's
 * function
 */
void print_dhcp_option_name(const u_char *bp_vend, int i,
                            int length) {

    if (i + 1 > length || i + bp_vend[i + 1] > length)
        return;

    int j;
    for (j = 1; j <= bp_vend[i + 1]; j++) {
        printf("%c", bp_vend[i + j + 1]);
    }
    printf("\n");
}

/**
 * @brief Used for print integer in the vendor specific print's
 * function
 */
void print_dhcp_option_int(const u_char *bp_vend, int i, int length) {

    if (i + 5 > length || bp_vend[i + 1] != 4)
        return;

    uint32_t j = 0;
    j += bp_vend[i + 2] << 24;
    j += bp_vend[i + 3] << 16;
    j += bp_vend[i + 4] << 8;
    j += bp_vend[i + 5];
    printf("%d", j);
    printf("\n");
}

/**
 * @brief
 * This function is used to print the vendor specific information.
 * There is a lot of line, they all print options and their content
 * which can be an IP address, a name or a number.
 */
void bootp_vendor_specific(const u_char *bp_vend, int length,
                           int verbose) {

    if (bp_vend[0] == 0x63 && bp_vend[1] == 0x82 &&
        bp_vend[2] == 0x53 && bp_vend[3] == 0x63) {
        PRV2(printf(RED "Dhcp" NC "\t\t"), verbose);
        // Multiple lines from the dhcp header
        PRV3(printf("\n" GRN "DHCP protocol" NC "\n"), verbose);
    }

    int i = 0, j;
    while (bp_vend[i] != TAG_END && i < length) {

        switch (bp_vend[i]) {

        case TAG_PAD:
            break;

        // RFC1048
        case TAG_SUBNET_MASK:
            PRV3(printf("Subnet mask : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            PRV3(printf("Time offset : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += 5;
            break;
        case TAG_GATEWAY:
            PRV3(printf("Router : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_SERVER:
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NAME_SERVER:
            PRV3(printf("Name server : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAIN_SERVER:
            PRV3(printf("DNS : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOG_SERVER:
            PRV3(printf("Log server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_COOKIE_SERVER:
            PRV3(printf("Cookie server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LPR_SERVER:
            PRV3(printf("LPR server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IMPRESS_SERVER:
            PRV3(printf("Impress server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RLP_SERVER:
            PRV3(printf("RLP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_HOSTNAME:
            PRV3(printf("Hostname : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTSIZE:
            PRV3(printf("Boot size : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC1497
        case TAG_DUMPPATH:
            PRV3(printf("Dump path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAINNAME:
            PRV3(printf("Domain name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SWAP_SERVER:
            PRV3(printf("Swap server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ROOTPATH:
            PRV3(printf("Root path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTPATH:
            PRV3(printf("Extension path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC2132
        case TAG_IP_FORWARD:
            PRV3(printf("IP forward : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NL_SRCRT:
            PRV3(printf("Non-local source routing : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PFILTERS:
            PRV3(printf("Policy filters : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REASS_SIZE:
            PRV3(printf("Maximum datagram reassembly size : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DEF_TTL:
            PRV3(printf("Default IP time-to-live : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TIMEOUT:
            PRV3(printf("Path MTU aging timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TABLE:
            PRV3(printf("MTU table : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_INT_MTU:
            PRV3(printf("Interface MTU : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOCAL_SUBNETS:
            PRV3(printf("All subnets are local : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BROAD_ADDR:
            PRV3(printf("Broadcast : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_MASK_DISC:
            PRV3(printf("Perform mask discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SUPPLY_MASK:
            PRV3(printf("Supply mask to other hosts : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_RDISC:
            PRV3(printf("Perform router discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RTR_SOL_ADDR:
            PRV3(printf("Router solicitation address : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STATIC_ROUTE:
            PRV3(printf("Static route : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_USE_TRAILERS:
            PRV3(printf("Trailer encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ARP_TIMEOUT:
            PRV3(printf("ARP cache timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ETH_ENCAP:
            PRV3(printf("Ethernet encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_TTL:
            PRV3(printf("TCP default TTL : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_KEEPALIVE:
            PRV3(printf("TCP keepalive interval : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_KEEPALIVE_GO:
            PRV3(printf("TCP keepalive garbage : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_DOMAIN:
            PRV3(printf("NIS domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            break;
            i += bp_vend[i + 1] + 1;
        case TAG_NIS_SERVERS:
            PRV3(printf("NIS servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NTP_SERVERS:
            PRV3(printf("NTP servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_OPTS:
            PRV3(printf("Vendor specific information : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NS:
            PRV3(printf("Netbios name server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_DDS:
            PRV3(printf("Netbios datagram distribution server : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NODE:
            PRV3(printf("Netbios node type : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_SCOPE:
            PRV3(printf("Netbios scope : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_FS:
            PRV3(printf("X Window font server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_DM:
            PRV3(printf("X Window display manager : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_DOMAIN:
            PRV3(printf("NIS+ domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_SERVERS:
            PRV3(printf("NIS+ servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MOBILE_HOME:
            PRV3(printf("Mobile IP home agent : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SMPT_SERVER:
            PRV3(printf("SMPT server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_POP3_SERVER:
            PRV3(printf("POP3 server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NNTP_SERVER:
            PRV3(printf("NNTP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_WWW_SERVER:
            PRV3(printf("WWW server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FINGER_SERVER:
            PRV3(printf("Finger server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IRC_SERVER:
            PRV3(printf("IRC server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_SRVR:
            PRV3(printf("Streettalk server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_STDA:
            PRV3(printf("Streettalk directory assistance : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // DHCP options
        case TAG_REQUESTED_IP:
            PRV3(printf("Requested IP address : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IP_LEASE:
            PRV3(printf("Lease time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += 5;
            break;
        case TAG_OPT_OVERLOAD:
            PRV3(printf("Overload : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TFTP_SERVER:
            PRV3(printf("TFTP server : "), verbose);
            for (j = 0; j < bp_vend[i + 1]; j++)
                PRV3(printf("%c", bp_vend[i + 2 + j]), verbose);
            PRV3(printf("\n"), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTFILENAME:
            PRV3(printf("Bootfile : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DHCP_MESSAGE:
            PRV3(printf("DHCP message type : "), verbose);
            for (j = 1; j <= bp_vend[i + 1]; j++) {
                switch (bp_vend[i + 1 + j]) {
                case DHCPDISCOVER:
                    PRV2(printf("Discover, "), verbose);
                    PRV3(printf("Discover "), verbose);
                    break;
                case DHCPOFFER:
                    PRV2(printf("Offer, "), verbose);
                    PRV3(printf("Offer "), verbose);
                    break;
                case DHCPREQUEST:
                    PRV2(printf("Request, "), verbose);
                    PRV3(printf("Request "), verbose);
                    break;
                case DHCPDECLINE:
                    PRV2(printf("Decline, "), verbose);
                    PRV3(printf("Decline "), verbose);
                    break;
                case DHCPACK:
                    PRV2(printf("Ack, "), verbose);
                    PRV3(printf("Ack "), verbose);
                    break;
                case DHCPNAK:
                    PRV2(printf("Nack, "), verbose);
                    PRV3(printf("Nack "), verbose);
                    break;
                case DHCPRELEASE:
                    PRV2(printf("Release, "), verbose);
                    PRV3(printf("Release "), verbose);
                    break;
                case DHCPINFORM:
                    PRV2(printf("Inform, "), verbose);
                    PRV3(printf("Inform "), verbose);
                    break;
                default:
                    break;
                }
                PRV3(printf("\n"), verbose);
            }

            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_ID:
            PRV3(printf("DHCP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PARM_REQUEST:
            PRV3(printf("Parameter request list :\n"), verbose);
            parameter_request_list_print(bp_vend, i + 2, verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MESSAGE:
            PRV3(printf("Message : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MAX_MSG_SIZE:
            PRV3(printf("Maximum DHCP message size : "), verbose);
            PRV3(
                printf("%d\n", bp_vend[i + 2] * 256 + bp_vend[i + 3]),
                verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RENEWAL_TIME:
            PRV3(printf("Renewal time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REBIND_TIME:
            PRV3(printf("Rebinding time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_CLASS:
            PRV3(printf("Vendor class identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ID:
            PRV3(printf("Client identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2241
        case TAG_NDS_SERVERS:
            PRV3(printf("NDS servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_TREE_NAME:
            PRV3(printf("NDS tree name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_CONTEXT:
            PRV3(printf("NDS context : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2485
        case TAG_OPEN_GROUP_UAP:
            PRV3(printf("Open Group's User Authentication "
                        "Protocol : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2563
        case TAG_DISABLE_AUTOCONF:
            PRV3(printf("Disable Autoconfiguration : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2610
        case TAG_SLP_DA:
            PRV3(printf("Service Location Protocol Directory "
                        "Agent : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_SCOPE:
            PRV3(printf("Service Location Protocol Scope : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2937
        case TAG_NS_SEARCH:
            PRV3(printf("NetBIOS over TCP/IP Name Server Search "
                        "Order : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 3011
        case TAG_IP4_SUBNET_SELECT:
            PRV3(printf("IP4 subnet select : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // Bootp extensions
        case TAG_USER_CLASS:
            PRV3(printf("User class : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_NAMING_AUTH:
            PRV3(printf("Service Location Protocol Naming "
                        "Authority : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_FQDN:
            PRV3(printf("Client Fully Qualified Domain Name : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_CIRCUIT:
            PRV3(printf("Agent Information Option :\n"), verbose);
            switch (bp_vend[i + 2]) {
            case 1:
                PRV3(printf("- Circuit ID : "), verbose);
                for (j = 0; j < bp_vend[i + 3]; j++)
                    PRV3(printf("%0x", bp_vend[i + 4 + j]), verbose);
                PRV3(printf("\n"), verbose);
                break;
            case 2:
                PRV3(printf("- Remote ID : "), verbose);
                for (j = 0; j < bp_vend[i + 3]; j++)
                    PRV3(printf("%0x", bp_vend[i + 4 + j]), verbose);
                PRV3(printf("\n"), verbose);
                break;
            default:
                break;
            }
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_MASK:
            PRV3(printf("Agent Subnet Mask : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TZ_STRING:
            PRV3(printf("Time Zone String : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FQDN_OPTION:
            PRV3(printf("Fully Qualified Domain Name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AUTH:
            PRV3(printf("Authentication :\n"), verbose);
            switch (bp_vend[i + 2]) {
            case 1:
                PRV3(printf("- Protocol : Delayed "
                            "authentification\n"),
                     verbose);
                break;
            case 2:
                PRV3(printf("- Protocol : Reconfigure key\n"),
                     verbose);
                break;
            case 3:
                PRV3(printf("- Protocol : HMAC-MD5\n"), verbose);
                break;
            case 4:
                PRV3(printf("- Protocol : HMAC-SHA1\n"), verbose);
                break;
            default:
                break;
            }

            PRV3(printf("Algorithm : "), verbose);
            switch (bp_vend[i + 3]) {
            case 1:
                PRV3(printf("HMAC-MD5\n"), verbose);
                break;
            case 2:
                PRV3(printf("HMAC-SHA1\n"), verbose);
                break;
            default:
                break;
            }

            PRV3(printf("RDM : "), verbose);
            switch (bp_vend[i + 4]) {
            case 0:
                PRV3(printf("Monotonically-increasing counter\n"),
                     verbose);
                break;
            case 1:
                PRV3(printf("Replay detection\n"), verbose);
                break;
            case 2:
                PRV3(printf("Replay detection and "
                            "broadcast/multicast\n"),
                     verbose);
                break;
            default:
                break;
            }
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VINES_SERVERS:
            PRV3(printf("Vines servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_RANK:
            PRV3(printf("Server rank : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ARCH:
            PRV3(printf("Client architecture : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_NDI:
            PRV3(printf("Client network device interface : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_GUID:
            PRV3(printf("Client GUID : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LDAP_URL:
            PRV3(printf("LDAP URL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_6OVER4:
            PRV3(printf("6over4 : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PRINTER_NAME:
            PRV3(printf("Printer name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MDHCP_SERVER:
            PRV3(printf("MDHCP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IPX_COMPAT:
            PRV3(printf("IPX compatibility : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT:
            PRV3(printf("NetInfo parent server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT_TAG:
            PRV3(printf("NetInfo parent server tag : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_URL:
            PRV3(printf("URL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FAILOVER:
            PRV3(printf("Failover : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_REQUEST:
            PRV3(printf("Extended request : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_OPTION:
            PRV3(printf("Extended option : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i, length), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SIP_SERVER:
            PRV3(printf("SIP server : "), verbose);
            for (j = 2; j <= bp_vend[i + 1]; j++) {
                if ((j != 2 && j != bp_vend[i + 1] + 1) && j % 4 != 1)
                    PRV3(printf("."), verbose);

                PRV3(printf("%d", bp_vend[i + j + 1]), verbose);

                if (j % 4 == 0 && j != bp_vend[i + 1])
                    PRV3(printf(" "), verbose);
            }
            PRV3(printf("\n"), verbose);

            i += bp_vend[i + 1] + 1;
            break;

        case TAG_END:
            i = 64;
            break;
        default:
            break;
        }
        i++;
    }

    PRV2(printf("Length : %d bits\n", length), verbose);
}

void parameter_request_list_print(const u_char *bp_vend, int start,
                                  int verbose) {
    int i, length = bp_vend[start + 1] + start;

    for (i = start; i < length; i++) {
        switch (bp_vend[i]) {
        case TAG_SUBNET_MASK:
            PRV3(printf("- Subnet mask\n"), verbose);
            break;
        case TAG_TIME_OFFSET:
            PRV3(printf("- Time offset\n"), verbose);
            break;
        case TAG_GATEWAY:
            PRV3(printf("- Router\n"), verbose);
            break;
        case TAG_TIME_SERVER:
            PRV3(printf("- Time server\n"), verbose);
            break;
        case TAG_NAME_SERVER:
            break;
            PRV3(printf("- Name server\n"), verbose);
        case TAG_DOMAIN_SERVER:
            PRV3(printf("- Domain name\n"), verbose);
            break;

            // to complete ...
        }
    }
}
