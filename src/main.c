#include "../include/1_ethernet.h"
#include "../include/2_arp.h"
#include "../include/2_ip.h"
#include "../include/2_ipv6.h"
#include "../include/3_tcp.h"
#include "../include/3_udp.h"

#include "../include/include.h"
#include "../include/option.h"

/**
 * @brief Take the packet read by pcap_loop and print each header with
 * calling Physical, Network and Transport layer analyzers. Transport
 * layers call Application layer analyzers.
 * @param args - contain the verbose level
 * @param header - contain the timestamp and the length of the packet
 * @param packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    int verbose = (int)args[0] - 48;
    int length = header->len;

    // Ethernet Header
    struct ether_header *eth_header =
        ethernet_analyzer(packet, verbose);
    packet += sizeof(struct ether_header);
    length -= sizeof(struct ether_header);

    // Network Layer
    struct iphdr *ip_header;
    struct ip6_hdr *ipv6_header;
    struct ether_arp *arp_header;

    // Transport Layer
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // Get the network protocol
    switch (htons(eth_header->ether_type)) {

    // IPv4 protocol
    case ETHERTYPE_IP:

        ip_header = ip_analyzer(packet, verbose);
        packet += ip_header->ihl * 4;
        length -= ip_header->ihl * 4;

        // TCP protocol
        if (ip_header->protocol == IPPROTO_TCP) {

            tcp_header = tcp_analyzer(packet, verbose);
            packet += tcp_header->th_off * 4;
            length -= tcp_header->th_off * 4;

            // Get the application layer protocol
            get_protocol_tcp(packet, tcp_header, length, verbose);
        }

        // UDP protocol
        else if (ip_header->protocol == IPPROTO_UDP) {

            udp_header = udp_analyzer(packet, verbose);
            packet += sizeof(struct udphdr);
            length -= sizeof(struct udphdr);

            // Get the application layer protocol
            get_protocol_udp(packet, udp_header, length, verbose);
        }

        break;

    // IPv6 protocol
    case ETHERTYPE_IPV6:

        ipv6_header = ipv6_analyzer(packet, verbose);
        packet += sizeof(struct ip6_hdr);
        length -= sizeof(struct ip6_hdr);

        // TCP protocol
        if (ipv6_header->ip6_nxt == IPPROTO_TCP) {

            tcp_header = tcp_analyzer(packet, verbose);
            packet += tcp_header->th_off * 4;
            length -= tcp_header->th_off * 4;

            get_protocol_tcp(packet, tcp_header, length, verbose);
        }

        // UDP protocol
        else if (ipv6_header->ip6_nxt == IPPROTO_UDP) {

            udp_header = udp_analyzer(packet, verbose);
            packet += sizeof(struct udphdr);
            length -= sizeof(struct udphdr);

            // Get the application layer protocol
            get_protocol_udp(packet, udp_header, length, verbose);
        }

        break;

    // ARP protocol
    case ETHERTYPE_ARP:
        arp_header = arp_analyzer(packet, verbose);
        packet += sizeof(struct ether_arp);
        (void)arp_header;
        break;

    default:
        break;
    }

    printf(COLOR_BANNER "\n");
}

/**
 * @brief Main function
 * @param argc
 * @param argv
 */
int main(int argc, char **argv) {

    usage_t *usage = malloc(sizeof(usage_t));
    init_usage(usage);

    // Check options
    if (option(argc, argv, usage) == 1)
        return 1;

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Option chosen
    if (usage->interface != NULL) {

        if ((handle = pcap_open_live(usage->interface, BUFSIZ, 1,
                                     1000, errbuf)) == NULL) {

            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }

        printf(COLOR_BANNER "\n");

        pcap_loop(handle, -1, got_packet, &usage->level);

    } else if (usage->file != NULL) {

        if ((handle = pcap_open_offline(usage->file, errbuf)) ==
            NULL) {
            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }

        printf(COLOR_BANNER "\n");

        pcap_loop(handle, -1, got_packet, &usage->level);

    } else {

        fprintf(stderr, "Error : No option chosen\n");
        exit(1);
    }

    return 0;
}