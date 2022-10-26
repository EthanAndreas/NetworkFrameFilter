#include "../include/4_bootp.h"

void bootp_analyzer(const u_char *packet, int verbose) {

    struct bootp *bootp_header = (struct bootp *)packet;

    if (bootp_header->bp_op == BOOTREQUEST)
        printf("Request, ");
    else if (bootp_header->bp_op == BOOTREPLY)
        printf("Reply, ");

    if (bootp_header->bp_htype == HTYPE_ETHER)
        printf("Ethernet, ");

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
        PRV1(printf("DHCP protocol\n"), verbose);
    }

    int i = 0, j;
    while (bp_vend[i] != TAG_END) {

        switch (bp_vend[i]) {

        case TAG_PAD:
            break;

        // RFC1048
        case TAG_SUBNET_MASK:
            PRV3(printf("Subnet mask : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            PRV3(printf("Time offset : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += 5;
            break;
        case TAG_GATEWAY:
            PRV3(printf("Router : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_SERVER:
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NAME_SERVER:
            PRV3(printf("Name server : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAIN_SERVER:
            PRV3(printf("DNS : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOG_SERVER:
            PRV3(printf("Log server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_COOKIE_SERVER:
            PRV3(printf("Cookie server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LPR_SERVER:
            PRV3(printf("LPR server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IMPRESS_SERVER:
            PRV3(printf("Impress server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RLP_SERVER:
            PRV3(printf("RLP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_HOSTNAME:
            PRV3(printf("Hostname : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTSIZE:
            PRV3(printf("Boot size : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC1497
        case TAG_DUMPPATH:
            PRV3(printf("Dump path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAINNAME:
            PRV3(printf("Domain name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SWAP_SERVER:
            PRV3(printf("Swap server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ROOTPATH:
            PRV3(printf("Root path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTPATH:
            PRV3(printf("Extension path : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC2132
        case TAG_IP_FORWARD:
            PRV3(printf("IP forward : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NL_SRCRT:
            PRV3(printf("Non-local source routing : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PFILTERS:
            PRV3(printf("Policy filters : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REASS_SIZE:
            PRV3(printf("Maximum datagram reassembly size : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DEF_TTL:
            PRV3(printf("Default IP time-to-live : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TIMEOUT:
            PRV3(printf("Path MTU aging timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TABLE:
            PRV3(printf("MTU table : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_INT_MTU:
            PRV3(printf("Interface MTU : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOCAL_SUBNETS:
            PRV3(printf("All subnets are local : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BROAD_ADDR:
            PRV3(printf("Broadcast : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_MASK_DISC:
            PRV3(printf("Perform mask discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SUPPLY_MASK:
            PRV3(printf("Supply mask to other hosts : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_RDISC:
            PRV3(printf("Perform router discovery : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RTR_SOL_ADDR:
            PRV3(printf("Router solicitation address : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STATIC_ROUTE:
            PRV3(printf("Static route : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_USE_TRAILERS:
            PRV3(printf("Trailer encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ARP_TIMEOUT:
            PRV3(printf("ARP cache timeout : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ETH_ENCAP:
            PRV3(printf("Ethernet encapsulation : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_TTL:
            PRV3(printf("TCP default TTL : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_KEEPALIVE:
            PRV3(printf("TCP keepalive interval : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_KEEPALIVE_GO:
            PRV3(printf("TCP keepalive garbage : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_DOMAIN:
            PRV3(printf("NIS domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            break;
            i += bp_vend[i + 1] + 1;
        case TAG_NIS_SERVERS:
            PRV3(printf("NIS servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NTP_SERVERS:
            PRV3(printf("NTP servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_OPTS:
            PRV3(printf("Vendor specific information : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NS:
            PRV3(printf("Netbios name server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_DDS:
            PRV3(printf("Netbios datagram distribution server : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NODE:
            PRV3(printf("Netbios node type : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_SCOPE:
            PRV3(printf("Netbios scope : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_FS:
            PRV3(printf("X Window font server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_DM:
            PRV3(printf("X Window display manager : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_DOMAIN:
            PRV3(printf("NIS+ domain : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_SERVERS:
            PRV3(printf("NIS+ servers : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MOBILE_HOME:
            PRV3(printf("Mobile IP home agent : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SMPT_SERVER:
            PRV3(printf("SMPT server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_POP3_SERVER:
            PRV3(printf("POP3 server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NNTP_SERVER:
            PRV3(printf("NNTP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_WWW_SERVER:
            PRV3(printf("WWW server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FINGER_SERVER:
            PRV3(printf("Finger server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IRC_SERVER:
            PRV3(printf("IRC server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_SRVR:
            PRV3(printf("Streettalk server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_STDA:
            PRV3(printf("Streettalk directory assistance : "),
                 verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // DHCP options
        case TAG_REQUESTED_IP:
            PRV3(printf("Requested IP address : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IP_LEASE:
            PRV3(printf("Lease time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += 5;
            break;
        case TAG_OPT_OVERLOAD:
            PRV3(printf("Overload : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TFTP_SERVER:
            PRV3(printf("TFTP server\n"), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTFILENAME:
            PRV3(printf("Bootfile : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DHCP_MESSAGE:
            PRV3(printf("DHCP options : "), verbose);
            // print the message type of dhcp
            for (j = 1; j <= bp_vend[i + 1]; j++) {
                switch (bp_vend[i + 1 + j]) {
                case DHCPDISCOVER:
                    PRV3(printf("Discover\n"), verbose);
                    break;
                case DHCPOFFER:
                    PRV3(printf("Offer\n"), verbose);
                    break;
                case DHCPREQUEST:
                    PRV3(printf("Request\n"), verbose);
                    break;
                case DHCPDECLINE:
                    PRV3(printf("Decline\n"), verbose);
                    break;
                case DHCPACK:
                    PRV3(printf("Ack\n"), verbose);
                    break;
                case DHCPNAK:
                    PRV3(printf("Nack\n"), verbose);
                    break;
                case DHCPRELEASE:
                    PRV3(printf("Release\n"), verbose);
                    break;
                case DHCPINFORM:
                    PRV3(printf("Inform\n"), verbose);
                    break;
                default:
                    break;
                }
            }

            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_ID:
            PRV3(printf("DHCP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PARM_REQUEST:
            PRV3(printf("Parameter request list"), verbose);
            // PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MESSAGE:
            PRV3(printf("Message : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MAX_MSG_SIZE:
            PRV3(printf("Maximum DHCP message size : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RENEWAL_TIME:
            PRV3(printf("Renewal time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REBIND_TIME:
            PRV3(printf("Rebinding time : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_CLASS:
            PRV3(printf("Vendor class identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ID:
            PRV3(printf("Client identifier : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2241
        case TAG_NDS_SERVERS:
            PRV3(printf("NDS servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_TREE_NAME:
            PRV3(printf("NDS tree name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_CONTEXT:
            PRV3(printf("NDS context : "), verbose);
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
            PRV3(printf("Disable Autoconfiguration : "), verbose);
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
            PRV3(printf("Service Location Protocol Scope : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2937
        case TAG_NS_SEARCH:
            PRV3(printf("NetBIOS over TCP/IP Name Server Search "
                        "Order : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 3011
        case TAG_IP4_SUBNET_SELECT:
            PRV3(printf("IP4 subnet select : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // Bootp extensions
        case TAG_USER_CLASS:
            PRV3(printf("User class : "), verbose);
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
            PRV3(printf("Client Fully Qualified Domain Name : "),
                 verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_CIRCUIT:
            PRV3(printf("Agent Circuit ID : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_MASK:
            PRV3(printf("Agent Subnet Mask : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TZ_STRING:
            PRV3(printf("Time Zone String : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FQDN_OPTION:
            PRV3(printf("Fully Qualified Domain Name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AUTH:
            PRV3(printf("Authentication\n"), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VINES_SERVERS:
            PRV3(printf("Vines servers : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_RANK:
            PRV3(printf("Server rank : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ARCH:
            PRV3(printf("Client architecture : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_NDI:
            PRV3(printf("Client network device interface : "),
                 verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_GUID:
            PRV3(printf("Client GUID : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LDAP_URL:
            PRV3(printf("LDAP URL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_6OVER4:
            PRV3(printf("6over4 : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PRINTER_NAME:
            PRV3(printf("Printer name : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MDHCP_SERVER:
            PRV3(printf("MDHCP server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IPX_COMPAT:
            PRV3(printf("IPX compatibility : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT:
            PRV3(printf("NetInfo parent server : "), verbose);
            PRV3(print_dhcp_option_addr(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT_TAG:
            PRV3(printf("NetInfo parent server tag : "), verbose);
            PRV3(print_dhcp_option_int(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_URL:
            PRV3(printf("URL : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FAILOVER:
            PRV3(printf("Failover : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_REQUEST:
            PRV3(printf("Extended request : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_OPTION:
            PRV3(printf("Extended option : "), verbose);
            PRV3(print_dhcp_option_name(bp_vend, i), verbose);
            i += bp_vend[i + 1] + 1;
            break;

        // Add
        case TAG_SIP_SERVER:
            PRV3(printf("SIP server : "), verbose);
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