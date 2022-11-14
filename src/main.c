#include "../include/1_ethernet.h"
#include "../include/2_arp.h"
#include "../include/2_ip.h"
#include "../include/2_ipv6.h"
#include "../include/3_tcp.h"
#include "../include/3_udp.h"

#include "../include/include.h"
#include "../include/option.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    int verbose = (int)args[0] - 48;

    // Ethernet Header
    struct ether_header *eth_header =
        ethernet_analyzer(packet, verbose);
    packet += sizeof(struct ether_header);

    // Network Layer
    struct iphdr *ip_header;
    struct ip6_hdr *ipv6_header;
    struct ether_arp *arp_header;

    // Transport Layer
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // Get the network protocol
    switch (htons(eth_header->ether_type)) {

    case ETHERTYPE_IP:
        ip_header = ip_analyzer(packet, verbose);
        packet += ip_header->ihl * 4;

        if (ip_header->protocol == IPPROTO_TCP) {

            tcp_header = tcp_analyzer(packet, verbose);
            packet += tcp_header->th_off * 4;

            get_protocol_tcp(packet, tcp_header,
                             ntohs(ip_header->tot_len) -
                                 ip_header->ihl * 4 -
                                 tcp_header->th_off * 4,
                             verbose);

        } else if (ip_header->protocol == IPPROTO_UDP) {

            udp_header = udp_analyzer(packet, verbose);
            packet += sizeof(struct udphdr);

            get_protocol_udp(packet, udp_header, udp_header->len,
                             verbose);
        }

        break;
    case ETHERTYPE_IPV6:
        ipv6_header = ipv6_analyzer(packet, verbose);
        packet += sizeof(struct ip6_hdr);

        if (ipv6_header->ip6_nxt == IPPROTO_TCP) {

            tcp_header = tcp_analyzer(packet, verbose);
            packet += tcp_header->th_off * 4;

            get_protocol_tcp(packet, tcp_header,
                             ntohs(ipv6_header->ip6_plen) -
                                 tcp_header->th_off * 4,
                             verbose);
        } else if (ipv6_header->ip6_nxt == IPPROTO_UDP) {

            udp_header = udp_analyzer(packet, verbose);
            packet += sizeof(struct udphdr);

            get_protocol_udp(packet, udp_header, udp_header->len,
                             verbose);
        }

        break;
    case ETHERTYPE_VLAN:
        // skip vlan header
        packet += 4;

        ipv6_header = ipv6_analyzer(packet, verbose);
        packet += sizeof(struct ip6_hdr);

        break;
    case ETHERTYPE_ARP:
        arp_header = arp_analyzer(packet, verbose);

        packet += sizeof(struct ether_arp);
        break;
    default:
        // For protocols that are not supported
        printf(RED "Unknown protocol" NC "\n");
    }

    (void)arp_header;

    printf(COLOR_BANNER "\n");
}

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