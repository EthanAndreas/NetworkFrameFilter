#include "../include/1_ethernet.h"
#include "../include/2_arp.h"
#include "../include/2_ip.h"
#include "../include/2_ipv6.h"
#include "../include/include.h"
#include "../include/option.h"

// frame number
volatile sig_atomic_t count = 0;

/**
 * @brief Take the packet read by pcap_loop and print each header with
 * calling Physical, Network and Transport layer analyzers. Transport
 * layers call Application layer analyzers.
 * @param args - contain the verbose verbose
 * @param header - contain the timestamp and the length of the packet
 * @param packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    int verbose = (int)args[0] - 48;
    int length = header->len;

    // One line by frame
    count++;
    PRV1(printf("%d\t", count), verbose);
    PRV1(printf("%d\t\t", length), verbose);

    // Ethernet Header
    struct ether_header *eth_header =
        ethernet_analyzer(packet, verbose);
    packet += sizeof(struct ether_header);
    length -= sizeof(struct ether_header);

    // Network Layer
    struct iphdr *ip_header;
    struct ip6_hdr *ipv6_header;

    // Get the network protocol
    switch (htons(eth_header->ether_type)) {

    // IPv4 protocol
    case ETHERTYPE_IP:
        ip_header = ip_analyzer(packet, verbose);
        packet += ip_header->ihl * 4;
        length -= ip_header->ihl * 4;
        // Get the transport layer protocol and the application layer
        get_protocol_ip(packet, ip_header, length, verbose);
        break;

    // IPv6 protocol
    case ETHERTYPE_IPV6:
        ipv6_header = ipv6_analyzer(packet, verbose);
        packet += sizeof(struct ip6_hdr);
        length -= sizeof(struct ip6_hdr);
        // Get the transport layer protocol and the application layer
        get_protocol_ipv6(packet, ipv6_header, length, verbose);
        break;

    // ARP protocol
    case ETHERTYPE_ARP:
        arp_analyzer(packet, verbose);
        packet += sizeof(struct ether_arp);
        PRV1(printf("-\t\t\tARP"), verbose);
        break;

    // other cases
    case ETHERTYPE_REVARP:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tRARP"), verbose);
        break;
    case ETHERTYPE_PUP:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tPUP"), verbose);
        break;
    case ETHERTYPE_SPRITE:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tSPRITE"), verbose);
        break;
    case ETHERTYPE_AT:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tAT"), verbose);
        break;
    case ETHERTYPE_AARP:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tAARP"), verbose);
        break;
    case ETHERTYPE_VLAN:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tVLAN"), verbose);
        break;
    case ETHERTYPE_IPX:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tIPX"), verbose);
        break;
    case ETHERTYPE_LOOPBACK:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\tLOOPBACK"), verbose);
        break;

    default:
        PRV1(add_mac_print_lvl1(eth_header), verbose);
        PRV1(printf("-\t\t\t" RED "Unknown" NC), verbose);
        break;
    }

    PRV1(printf("\n"), verbose);
    PRV2(printf(SIMPLE_BANNER "\n"), verbose);
    PRV3(printf(COLOR_BANNER "\n"), verbose);
}

/**
 * @brief Main function
 * @param argc
 * @param argv
 */
int main(int argc, char **argv) {

    // create usage structure
    usage_t *usage = malloc(sizeof(usage_t));
    init_usage(usage);

    // Check options
    option(argc, argv, usage);

    // Check verbose level
    int verbose = atoi((const char *)usage->verbose);
    if (verbose < 0 || verbose > 3) {
        fprintf(stderr, RED "Error : Verbose level must be 1,2,3 or "
                            "0 to launch without display" NC "\n");
        print_option();
        exit(EXIT_FAILURE);
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Port listening
    if (usage->interface != NULL) {

        // online mode
        SCHK(handle = pcap_open_live(usage->interface, BUFSIZ,
                                     PROMISC, TO_MS, errbuf));

        // Filter
        if (usage->filter != NULL) {

            struct bpf_program fp;
            CHK(pcap_compile(handle, &fp, usage->filter, 0,
                             PCAP_NETMASK_UNKNOWN));
            CHK(pcap_setfilter(handle, &fp));
        }

        // One line by frame
        PRV1(printf(GRN "No.\tLength (bits)\t"
                        "Source\t\t\t\t\t\tDestination\t\t\t\t\tPort"
                        "\t\t\tProtocol" NC "\n"),
             verbose);
        // One line by protocol
        PRV2(printf(SIMPLE_BANNER "\n"), verbose);
        // Multiple lines by frame
        PRV3(printf(COLOR_BANNER "\n"), verbose);

        // Capture packets
        pcap_loop(handle, -1, got_packet, (u_char *)usage->verbose);

        // Free pcap handle
        pcap_close(handle);
    }
    // File analyzing
    else if (usage->file != NULL) {

        // offline mode
        SCHK(handle = pcap_open_offline(usage->file, errbuf));

        // One line by frame
        PRV1(printf(GRN "No.\tLength (bits)\t"
                        "Source\t\t\t\t\t\tDestination\t\t\t\t\tPort"
                        "\t\t\tProtocol" NC "\n"),
             verbose);
        // One line by protocol
        PRV2(printf(SIMPLE_BANNER "\n"), verbose);
        // Multiple lines by frame
        PRV3(printf(COLOR_BANNER "\n"), verbose);

        // Analyze packets
        pcap_loop(handle, -1, got_packet, (u_char *)usage->verbose);

        // Free pcap handle
        pcap_close(handle);

    } else {

        fprintf(stderr, RED "Error : No option picked" NC "\n");
        print_option();
        exit(EXIT_FAILURE);
    }

    // free usage structure
    free(usage);

    exit(EXIT_SUCCESS);
}