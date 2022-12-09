#include "../include/1_ethernet.h"
#include "../include/2_arp.h"
#include "../include/2_ip.h"
#include "../include/2_ipv6.h"
#include "../include/include.h"
#include "../include/option.h"

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

    // One line by frame
    int length = header->len;
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
        PRV1(printf("-\t\t\t-"), verbose);
        break;

    default:
        PRV1(printf("-\t\t\t\t\t\t-\t\t\t\t\t\t-\t\t\t" RED
                    "Unrecognized" NC),
             verbose);
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
    if (verbose < 1 || verbose > 3) {
        fprintf(stderr,
                RED "Error : Verbose level must be 1,2 or 3" NC "\n");
        print_option();
        exit(EXIT_FAILURE);
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Port listening
    if (usage->interface != NULL) {

        if ((handle = pcap_open_live(usage->interface, BUFSIZ,
                                     PROMISC, TO_MS, errbuf)) ==
            NULL) {
            fprintf(stderr, RED "%s" NC "\n", errbuf);
            exit(EXIT_FAILURE);
        }

        // Filter
        if (usage->filter != NULL) {
            struct bpf_program fp;
            if (pcap_compile(handle, &fp, usage->filter, 0,
                             PCAP_NETMASK_UNKNOWN) == -1) {
                fprintf(stderr, RED "Error : %s" NC "\n",
                        pcap_geterr(handle));
                exit(EXIT_FAILURE);
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, RED "Error : %s" NC "\n",
                        pcap_geterr(handle));
                exit(EXIT_FAILURE);
            }
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

        pcap_loop(handle, -1, got_packet, (u_char *)usage->verbose);

    }
    // File analyzing
    else if (usage->file != NULL) {

        if ((handle = pcap_open_offline(usage->file, errbuf)) ==
            NULL) {
            fprintf(stderr, RED "%s" NC "\n", errbuf);
            exit(EXIT_FAILURE);
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

        pcap_loop(handle, -1, got_packet, (u_char *)usage->verbose);

    } else {

        fprintf(stderr, RED "Error : No option picked" NC "\n");
        print_option();
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}