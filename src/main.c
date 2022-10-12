#include "../include/ethernet.h"
#include "../include/include.h"
#include "../include/ip_arp_rarp.h"
#include "../include/option.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    // Ethernet Header
    struct ether_header *eth_header = ethernet_analyzer(packet);

    // Protocol
    switch (htons(eth_header->ether_type)) {

    case ETHERTYPE_IP:
        ip_analyzer(packet);
        break;

    case ETHERTYPE_ARP:
        arp_analyzer(packet);
        break;

    case ETHERTYPE_REVARP:
        // rarp_analyzer(packet, eth_header);
        break;

    default:
        printf("Unknown protocol\n");
    }

    // affichage paquet
    // for (int i = 0; i < header->caplen; i++) {
    //     printf("%02x ", packet[i]);
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
    } else {

        fprintf(stderr, "Error : No option chosen\n");
        exit(1);
    }

    return 0;
}