#include "../include/4_bootp.h"

void bootp_analyzer(const u_char *packet, int verbose) {

    struct bootp *bootp_header = (struct bootp *)packet;

    printf(GRN "Bootp protocol" NC "\n");

    if (bootp_header->bp_op == BOOTREQUEST)
        PRV1(printf("Request\n"), verbose);
    else if (bootp_header->bp_op == BOOTREPLY)
        PRV1(printf("Reply\n"), verbose);

    if (bootp_header->bp_htype == HTYPE_ETHER)
        PRV1(printf("Ethernet\n"), verbose);

    // print transaction id in frame form
    PRV1(printf("Transaction ID : %02x:%02x:%02x:%02x\n",
                bootp_header->bp_xid[0], bootp_header->bp_xid[1],
                bootp_header->bp_xid[2], bootp_header->bp_xid[3]),
         verbose);

    PRV2(printf("\tClient IP address : %s\n",
                inet_ntoa(bootp_header->bp_ciaddr)),
         verbose);

    PRV2(printf("\tYour IP address : %s\n",
                inet_ntoa(bootp_header->bp_yiaddr)),
         verbose);

    PRV2(printf("\tServer IP address : %s\n",
                inet_ntoa(bootp_header->bp_siaddr)),
         verbose);

    PRV2(printf("\tGateway IP address : %s\n",
                inet_ntoa(bootp_header->bp_giaddr)),
         verbose);

    PRV2(printf("\tClient hardware address : %s\n",
                ether_ntoa(
                    (struct ether_addr *)bootp_header->bp_chaddr)),
         verbose);

    PRV3(printf("\t\tHardware address length : %d\n"
                "\t\tHops : %d\n"
                "\t\tSeconds since boot began : %d\n"
                "\t\tFlags : %d\n",
                bootp_header->bp_hlen, bootp_header->bp_hops,
                bootp_header->bp_secs, bootp_header->bp_flags),
         verbose);

    if (bootp_header->bp_sname[0] == '\0')
        PRV3(printf("\t\tServer host name : not given\n"), verbose);
    else
        PRV3(printf("\t\tServer host name : %s\n",
                    bootp_header->bp_sname),
             verbose);

    if (bootp_header->bp_file[0] == '\0')
        PRV3(printf("\t\tBoot file name : not given\n"), verbose);
    else
        PRV3(printf("\t\tBoot file name : %s\n",
                    bootp_header->bp_file),
             verbose);

    bootp_vendor_specific(bootp_header->bp_vend, verbose);
}

/**
 * @brief Used for print IP address in the vendor specific print's
 * function
 */
void print_dhcp_option_addr(uint8_t bp_vend[64], int i) {

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
void print_dhcp_option_name(uint8_t bp_vend[64], int i) {

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
void print_dhcp_option_int(uint8_t bp_vend[64], int i) {

    uint32_t time = 0;
    time += bp_vend[i + 2] << 24;
    time += bp_vend[i + 3] << 16;
    time += bp_vend[i + 4] << 8;
    time += bp_vend[i + 5];
    printf("%d\n", time);
}

/**
 * @brief
 * This function is used to print the vendor specific information.
 * There is a lot of line, they all print options and their content
 * which can be an IP address, a name or a number.
 */
void bootp_vendor_specific(uint8_t bp_vend[64], int verbose) {

    /*
    problème sur tftp au niveau du contenu
    problème sur agent remote : detecté au mauvais endroit
    */

    /*
    objectif : faire une première analyse pour récupérer la taille de
    la trame avec TAG_END et ensuite détecter les options
    */

    if (bp_vend[0] == 0x63 && bp_vend[1] == 0x82 &&
        bp_vend[2] == 0x53 && bp_vend[3] == 0x63) {
        PRV1(printf(GRN "DHCP protocol" NC "\n"), verbose);
    }

    int i = 0, j;
    while (bp_vend[i] != TAG_END) {

        switch (bp_vend[i]) {

        case TAG_PAD:
            break;

        // RFC1048
        case TAG_SUBNET_MASK:
            PRV2(printf("\tSubnet mask : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            PRV2(printf("\tTime offset : "), verbose);
            PRV2(print_dhcp_option_int(bp_vend, i), verbose);
            i += 5;
            break;
        case TAG_GATEWAY:
            PRV2(printf("\tRouter : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_SERVER:
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NAME_SERVER:
            PRV3(printf("\t\tName server : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAIN_SERVER:
            PRV2(printf("\tDNS : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOG_SERVER:
            PRV3(printf("\t\tLog server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_COOKIE_SERVER:
            PRV3(printf("\t\tCookie server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LPR_SERVER:
            PRV3(printf("\t\tLPR server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IMPRESS_SERVER:
            PRV3(printf("\t\tImpress server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RLP_SERVER:
            PRV3(printf("\t\tRLP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_HOSTNAME:
            PRV2(printf("\tHostname : "), verbose);
            PRV2(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTSIZE:
            PRV3(printf("\t\tBoot size : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC1497
        case TAG_DUMPPATH:
            PRV3(printf("\t\tDump path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAINNAME:
            PRV2(printf("\tDomain name : "), verbose);
            PRV2(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SWAP_SERVER:
            PRV3(printf("\t\tSwap server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ROOTPATH:
            PRV3(printf("\t\tRoot path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTPATH:
            PRV3(printf("\t\tExtension path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC2132
        case TAG_IP_FORWARD:
            PRV3(printf("\t\tIP forward : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NL_SRCRT:
            PRV3(printf("\t\tNon-local source routing : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PFILTERS:
            PRV3(printf("\t\tPolicy filters : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REASS_SIZE:
            PRV3(printf("\t\tMaximum datagram reassembly size : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DEF_TTL:
            PRV3(printf("\t\tDefault IP time-to-live : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TIMEOUT:
            PRV3(printf("\t\tPath MTU aging timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TABLE:
            PRV3(printf("\t\tMTU table : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_INT_MTU:
            PRV3(printf("\t\tInterface MTU : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOCAL_SUBNETS:
            PRV3(printf("\t\tAll subnets are local : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BROAD_ADDR:
            PRV2(printf("\tBroadcast : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_MASK_DISC:
            PRV3(printf("\t\tPerform mask discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SUPPLY_MASK:
            PRV3(printf("\t\tSupply mask to other hosts : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_RDISC:
            PRV3(printf("\t\tPerform router discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RTR_SOL_ADDR:
            PRV3(printf("\t\tRouter solicitation address : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STATIC_ROUTE:
            PRV3(printf("\t\tStatic route : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_USE_TRAILERS:
            PRV3(printf("\t\tTrailer encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ARP_TIMEOUT:
            PRV3(printf("\t\tARP cache timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ETH_ENCAP:
            PRV3(printf("\t\tEthernet encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_TTL:
            PRV3(printf("\t\tTCP default TTL : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_KEEPALIVE:
            PRV3(printf("\t\tTCP keepalive interval : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_KEEPALIVE_GO:
            PRV3(printf("\t\tTCP keepalive garbage : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_DOMAIN:
            PRV3(printf("\t\tNIS domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            break;
            i += bp_vend[i + 1] + 1;
        case TAG_NIS_SERVERS:
            PRV3(printf("\t\tNIS servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NTP_SERVERS:
            PRV3(printf("\t\tNTP servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_OPTS:
            PRV3(printf("\t\tVendor specific information : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NS:
            PRV2(printf("\tNetbios name server : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_DDS:
            PRV3(
                printf("\t\tNetbios datagram distribution server : "),
                verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NODE:
            PRV3(printf("\t\tNetbios node type : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_SCOPE:
            PRV2(printf("\tNetbios scope : "), verbose);
            PRV2(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_FS:
            PRV3(printf("\t\tX Window font server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_DM:
            PRV3(printf("\t\tX Window display manager : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_DOMAIN:
            PRV3(printf("\t\tNIS+ domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_SERVERS:
            PRV3(printf("\t\tNIS+ servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MOBILE_HOME:
            PRV3(printf("\t\tMobile IP home agent : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SMPT_SERVER:
            PRV3(printf("\t\tSMPT server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_POP3_SERVER:
            PRV3(printf("\t\tPOP3 server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NNTP_SERVER:
            PRV3(printf("\t\tNNTP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_WWW_SERVER:
            PRV3(printf("\t\tWWW server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FINGER_SERVER:
            PRV3(printf("\t\tFinger server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IRC_SERVER:
            PRV3(printf("\t\tIRC server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_SRVR:
            PRV3(printf("\t\tStreettalk server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_STDA:
            PRV3(printf("\t\tStreettalk directory assistance : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // DHCP options
        case TAG_REQUESTED_IP:
            PRV2(printf("\tRequested IP address : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IP_LEASE:
            PRV2(printf("\tLease time : "), verbose);
            PRV2(print_dhcp_option_int(bp_vend, i), verbose);
            i += 5;
            break;
        case TAG_OPT_OVERLOAD:
            PRV3(printf("\t\tOverload : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TFTP_SERVER:
            PRV3(printf("\t\tTFTP server\n"), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTFILENAME:
            PRV3(printf("\t\tBootfile : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DHCP_MESSAGE:
            PRV2(printf("\tDHCP message type : "), verbose);
            // print the message type of dhcp
            for (j = 1; j <= bp_vend[i + 1]; j++) {
                switch (bp_vend[i + 1 + j]) {
                case DHCPDISCOVER:
                    PRV2(printf("Discover "), verbose);
                    break;
                case DHCPOFFER:
                    PRV2(printf("Offer "), verbose);
                    break;
                case DHCPREQUEST:
                    PRV2(printf("Request "), verbose);
                    break;
                case DHCPDECLINE:
                    PRV2(printf("Decline "), verbose);
                    break;
                case DHCPACK:
                    PRV2(printf("Ack "), verbose);
                    break;
                case DHCPNAK:
                    PRV2(printf("Nack "), verbose);
                    break;
                case DHCPRELEASE:
                    PRV2(printf("Release "), verbose);
                    break;
                case DHCPINFORM:
                    PRV2(printf("Inform "), verbose);
                    break;
                default:
                    break;
                }
                PRV2(printf("\n"), verbose);
            }

            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_ID:
            PRV2(printf("\tDHCP server : "), verbose);
            PRV2(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PARM_REQUEST:
            PRV2(printf("\tParameter request list"), verbose);
            PRV2(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MESSAGE:
            PRV3(printf("\t\tMessage : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MAX_MSG_SIZE:
            PRV3(printf("\t\tMaximum DHCP message size : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RENEWAL_TIME:
            PRV3(printf("\t\tRenewal time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REBIND_TIME:
            PRV3(printf("\t\tRebinding time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_CLASS:
            PRV3(printf("\t\tVendor class identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ID:
            PRV3(printf("\t\tClient identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2241
        case TAG_NDS_SERVERS:
            PRV3(printf("\t\tNDS servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_TREE_NAME:
            PRV3(printf("\t\tNDS tree name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_CONTEXT:
            PRV3(printf("\t\tNDS context : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2485
        case TAG_OPEN_GROUP_UAP:
            PRV3(printf(
                     "Open Group's User Authentication Protocol : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2563
        case TAG_DISABLE_AUTOCONF:
            PRV3(printf("\t\tDisable Autoconfiguration : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2610
        case TAG_SLP_DA:
            PRV3(printf(
                     "Service Location Protocol Directory Agent : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_SCOPE:
            PRV3(printf("\t\tService Location Protocol Scope : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2937
        case TAG_NS_SEARCH:
            PRV3(printf("\t\tNetBIOS over TCP/IP Name Server Search "
                        "Order : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 3011
        case TAG_IP4_SUBNET_SELECT:
            PRV3(printf("\t\tIP4 subnet select : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // Bootp extensions
        case TAG_USER_CLASS:
            PRV3(printf("\t\tUser class : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_NAMING_AUTH:
            PRV3(printf(
                     "Service Location Protocol Naming Authority : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_FQDN:
            PRV3(printf("\t\tClient Fully Qualified Domain Name : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_CIRCUIT:
            PRV3(printf("\t\tAgent Circuit ID : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_MASK:
            PRV3(printf("\t\tAgent Subnet Mask : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TZ_STRING:
            PRV3(printf("\t\tTime Zone String : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FQDN_OPTION:
            PRV3(printf("\t\tFully Qualified Domain Name : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AUTH:
            PRV3(printf("\t\tAuthentication\n"), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VINES_SERVERS:
            PRV3(printf("\t\tVines servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_RANK:
            PRV3(printf("\t\tServer rank : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ARCH:
            PRV3(printf("\t\tClient architecture : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_NDI:
            PRV3(printf("\t\tClient network device interface : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_GUID:
            PRV3(printf("\t\tClient GUID : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LDAP_URL:
            PRV3(printf("\t\tLDAP URL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_6OVER4:
            PRV3(printf("\t\t6over4 : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PRINTER_NAME:
            PRV3(printf("\t\tPrinter name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MDHCP_SERVER:
            PRV3(printf("\t\tMDHCP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IPX_COMPAT:
            PRV3(printf("\t\tIPX compatibility : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT:
            PRV3(printf("\t\tNetInfo parent server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT_TAG:
            PRV3(printf("\t\tNetInfo parent server tag : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_URL:
            PRV3(printf("\t\tURL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FAILOVER:
            PRV3(printf("\t\tFailover : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_REQUEST:
            PRV3(printf("\t\tExtended request : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_OPTION:
            PRV3(printf("\t\tExtended option : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // Add
        case TAG_SIP_SERVER:
            PRV3(printf("\t\tSIP server : "), verbose);
            // There is the type in add to the length
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
}