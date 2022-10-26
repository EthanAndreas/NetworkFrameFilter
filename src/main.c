#include "../include/1_ethernet.h"
#include "../include/2_arp.h"
#include "../include/2_ip.h"
#include "../include/3_tcp.h"
#include "../include/3_udp.h"
#include "../include/4_bootp.h"
#include "../include/4_dns.h"

#include "../include/include.h"
#include "../include/option.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    // Ethernet Header
    struct ether_header *eth_header = ethernet_analyzer(packet);
    // keep the packet without the ethernet header
    packet += sizeof(struct ether_header);

    // Network Layer
    struct ip *ip_header;
    struct ether_arp *arp_header;

    // Transport Layer
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // Get the network protocol
    switch (htons(eth_header->ether_type)) {

    case ETHERTYPE_IP:

        // IP Header
        ip_header = ip_analyzer(packet);
        // keep the packet without the ip header
        packet += (ip_header->ip_hl * 4);

        // Get the transport protocol
        if (ip_header->ip_p == IPPROTO_TCP) {

            // TCP Header
            tcp_header = tcp_analyzer(packet, ip_header);
            // keep the packet without the tcp header
            packet += tcp_header->th_off;

            // Get the application protocol
            get_protocol_tcp(packet, tcp_header);

        } else if (ip_header->ip_p == IPPROTO_UDP) {

            // UDP Header
            udp_header = udp_analyzer(packet, ip_header);
            // keep the packet without the udp header
            packet += sizeof(struct udphdr);

            // Get the application protocol
            get_protocol_udp(packet, udp_header);
        }

        break;
    case ETHERTYPE_ARP:

        // ARP Header
        arp_header = arp_analyzer(packet);
        // keep the packet without the arp header
        packet += sizeof(struct ether_arp);
        break;
    default:
        // For protocols that are not supported
        printf("Unknown protocol\n");
    }

    (void)arp_header;

    // print paquet
    // for (int i = 0; i < header->len; i++) {
    //     printf("%02x ", packet[i]);
    //     if ((i + 1) % 16 == 0)
    //         printf("\n");
    // }

    printf("\n");
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

        pcap_loop(handle, -1, got_packet, NULL);

    } else if (usage->file != NULL) {

        if ((handle = pcap_open_offline(usage->file, errbuf)) ==
            NULL) {
            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }

        pcap_loop(handle, -1, got_packet, NULL);

    } else {

        fprintf(stderr, "Error : No option chosen\n");
        exit(1);
    }

    return 0;
}