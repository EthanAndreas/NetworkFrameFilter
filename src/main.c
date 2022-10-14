#include "../include/application_layer.h"
#include "../include/bootp.h"
#include "../include/ethernet.h"
#include "../include/include.h"
#include "../include/network_layer.h"
#include "../include/option.h"
#include "../include/transport_layer.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    // Ethernet Header
    struct ether_header *eth_header = ethernet_analyzer(packet);
    packet += sizeof(struct ether_header);

    // Protocol
    struct ip *ip_header;
    struct ether_arp *arp_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    switch (htons(eth_header->ether_type)) {

    case ETHERTYPE_IP:
        ip_header = ip_analyzer(packet);
        packet += (ip_header->ip_hl * 4);

        if (ip_header->ip_p == IPPROTO_TCP) {

            tcp_header = tcp_analyzer(packet, ip_header);
            packet += tcp_header->th_off;

            if (ntohs(tcp_header->th_dport) == DNS_PORT ||
                ntohs(tcp_header->th_sport) == DNS_PORT)
                dns_analyzer(packet, tcp_header->th_off * 4);

            if (ntohs(tcp_header->th_dport) == BOOTP_PORT ||
                ntohs(tcp_header->th_sport) == BOOTP_PORT)
                bootp_analyzer(packet, tcp_header->th_off * 4);
        }

        if (ip_header->ip_p == IPPROTO_UDP) {

            udp_header = udp_analyzer(packet, ip_header);
            packet += sizeof(struct udphdr);

            if (ntohs(udp_header->uh_dport) == DNS_PORT ||
                ntohs(udp_header->uh_sport) == DNS_PORT)
                dns_analyzer(packet, udp_header->uh_ulen * 4);

            if (ntohs(udp_header->uh_dport) == BOOTP_PORT ||
                ntohs(udp_header->uh_sport) == BOOTP_PORT)
                bootp_analyzer(packet, udp_header->uh_ulen * 4);
        }

        break;

    case ETHERTYPE_ARP:
        arp_header = arp_analyzer(packet);
        break;

    default:
        printf("Unknown protocol\n");
    }

    (void)arp_header;

    // print paquet
    // for (int i = 0; i < header->len; i++) {
    //     printf("%02x ", packet[i]);
    //     if ((i + 1) % 16 == 0)
    //         printf("\n");
    // }

    printf("\n\n");
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