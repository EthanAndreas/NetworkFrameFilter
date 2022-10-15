#include "../include/4_bootp.h"

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
void bootp_vendor_specific(uint8_t bp_vend[64]) {

    /*
    problème sur tftp au niveau du contenu
    problème sur agent remote : detecté au mauvais endroit
    */

    if (bp_vend[0] == 0x63 && bp_vend[1] == 0x82 &&
        bp_vend[2] == 0x53 && bp_vend[3] == 0x63) {
        printf("DHCP protocol\n");
    }

    int i = 0, j;
    while (bp_vend[i] != TAG_END) {

        switch (bp_vend[i]) {

        case TAG_PAD:
            break;

        // RFC1048
        case TAG_SUBNET_MASK:
            printf("Subnet mask : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_OFFSET:
            printf("Time offset : ");
            print_dhcp_option_int(bp_vend, i);
            i += 5;
            break;
        case TAG_GATEWAY:
            printf("Router : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TIME_SERVER:
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NAME_SERVER:
            printf("Name server : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAIN_SERVER:
            printf("DNS : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOG_SERVER:
            printf("Log server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_COOKIE_SERVER:
            printf("Cookie server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LPR_SERVER:
            printf("LPR server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IMPRESS_SERVER:
            printf("Impress server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RLP_SERVER:
            printf("RLP server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_HOSTNAME:
            printf("Hostname : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTSIZE:
            printf("Boot size : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC1497
        case TAG_DUMPPATH:
            printf("Dump path : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DOMAINNAME:
            printf("Domain name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SWAP_SERVER:
            printf("Swap server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ROOTPATH:
            printf("Root path : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTPATH:
            printf("Extension path : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC2132
        case TAG_IP_FORWARD:
            printf("IP forward : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NL_SRCRT:
            printf("Non-local source routing : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PFILTERS:
            printf("Policy filters : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REASS_SIZE:
            printf("Maximum datagram reassembly size : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DEF_TTL:
            printf("Default IP time-to-live : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TIMEOUT:
            printf("Path MTU aging timeout : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MTU_TABLE:
            printf("MTU table : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_INT_MTU:
            printf("Interface MTU : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LOCAL_SUBNETS:
            printf("All subnets are local : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BROAD_ADDR:
            printf("Broadcast : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_MASK_DISC:
            printf("Perform mask discovery : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SUPPLY_MASK:
            printf("Supply mask to other hosts : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DO_RDISC:
            printf("Perform router discovery : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RTR_SOL_ADDR:
            printf("Router solicitation address : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STATIC_ROUTE:
            printf("Static route : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_USE_TRAILERS:
            printf("Trailer encapsulation : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ARP_TIMEOUT:
            printf("ARP cache timeout : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_ETH_ENCAP:
            printf("Ethernet encapsulation : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_TTL:
            printf("TCP default TTL : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TCP_KEEPALIVE:
            printf("TCP keepalive interval : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_KEEPALIVE_GO:
            printf("TCP keepalive garbage : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_DOMAIN:
            printf("NIS domain : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_SERVERS:
            printf("NIS servers : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NTP_SERVERS:
            printf("NTP servers : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_OPTS:
            printf("Vendor specific information : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NS:
            printf("Netbios name server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_DDS:
            printf("Netbios datagram distribution server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_NODE:
            printf("Netbios node type : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETBIOS_SCOPE:
            printf("Netbios scope : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_FS:
            printf("X Window font server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_XWIN_DM:
            printf("X Window display manager : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_DOMAIN:
            printf("NIS+ domain : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NIS_P_SERVERS:
            printf("NIS+ servers : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MOBILE_HOME:
            printf("Mobile IP home agent : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SMPT_SERVER:
            printf("SMPT server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_POP3_SERVER:
            printf("POP3 server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NNTP_SERVER:
            printf("NNTP server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_WWW_SERVER:
            printf("WWW server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FINGER_SERVER:
            printf("Finger server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IRC_SERVER:
            printf("IRC server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_SRVR:
            printf("Streettalk server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_STREETTALK_STDA:
            printf("Streettalk directory assistance : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // DHCP options
        case TAG_REQUESTED_IP:
            printf("Requested IP address : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IP_LEASE:
            printf("Lease time : ");
            print_dhcp_option_int(bp_vend, i);
            i += 5;
            break;
        case TAG_OPT_OVERLOAD:
            printf("Overload : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TFTP_SERVER:
            printf("TFTP server\n");
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_BOOTFILENAME:
            printf("Bootfile : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_DHCP_MESSAGE:
            printf("DHCP options : ");
            // print the message type of dhcp
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
            printf("Parameter request list : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MESSAGE:
            printf("Message : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MAX_MSG_SIZE:
            printf("Maximum DHCP message size : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_RENEWAL_TIME:
            printf("Renewal time : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_REBIND_TIME:
            printf("Rebinding time : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VENDOR_CLASS:
            printf("Vendor class identifier : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ID:
            printf("Client identifier : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2241
        case TAG_NDS_SERVERS:
            printf("NDS servers : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_TREE_NAME:
            printf("NDS tree name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NDS_CONTEXT:
            printf("NDS context : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2485
        case TAG_OPEN_GROUP_UAP:
            printf("Open Group's User Authentication Protocol : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2563
        case TAG_DISABLE_AUTOCONF:
            printf("Disable Autoconfiguration : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2610
        case TAG_SLP_DA:
            printf("Service Location Protocol Directory Agent : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_SCOPE:
            printf("Service Location Protocol Scope : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 2937
        case TAG_NS_SEARCH:
            printf("NetBIOS over TCP/IP Name Server Search Order : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // RFC 3011
        case TAG_IP4_SUBNET_SELECT:
            printf("IP4 subnet select : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // Bootp extensions
        case TAG_USER_CLASS:
            printf("User class : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SLP_NAMING_AUTH:
            printf("Service Location Protocol Naming Authority : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_FQDN:
            printf("Client Fully Qualified Domain Name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_CIRCUIT:
            printf("Agent Circuit ID : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AGENT_MASK:
            printf("Agent Subnet Mask : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_TZ_STRING:
            printf("Time Zone String : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FQDN_OPTION:
            printf("Fully Qualified Domain Name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_AUTH:
            printf("Authentication\n");
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_VINES_SERVERS:
            printf("Vines servers : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_SERVER_RANK:
            printf("Server rank : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_ARCH:
            printf("Client architecture : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_NDI:
            printf("Client network device interface : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_CLIENT_GUID:
            printf("Client GUID : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_LDAP_URL:
            printf("LDAP URL : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_6OVER4:
            printf("6over4 : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_PRINTER_NAME:
            printf("Printer name : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_MDHCP_SERVER:
            printf("MDHCP server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_IPX_COMPAT:
            printf("IPX compatibility : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT:
            printf("NetInfo parent server : ");
            print_dhcp_option_addr(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_NETINFO_PARENT_TAG:
            printf("NetInfo parent server tag : ");
            print_dhcp_option_int(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_URL:
            printf("URL : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_FAILOVER:
            printf("Failover : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_REQUEST:
            printf("Extended request : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;
        case TAG_EXTENDED_OPTION:
            printf("Extended option : ");
            print_dhcp_option_name(bp_vend, i);
            i += bp_vend[i + 1] + 1;
            break;

        // Add
        case TAG_SIP_SERVER:
            printf("SIP server : ");
            // There is the type in add to the length
            for (j = 2; j <= bp_vend[i + 1]; j++) {
                if ((j != 2 && j != bp_vend[i + 1] + 1) && j % 4 != 1)
                    printf(".");

                printf("%d", bp_vend[i + j + 1]);

                if (j % 4 == 0 && j != bp_vend[i + 1])
                    printf(" ");
            }
            printf("\n");

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