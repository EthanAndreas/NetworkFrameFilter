#include "../include/include.h"

char *ether_ntoa_r(const struct ether_addr *addr, char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr->ether_addr_octet[0], addr->ether_addr_octet[1],
             addr->ether_addr_octet[2], addr->ether_addr_octet[3],
             addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

    // Ethernet Header
    struct ether_header *eth_header;
    static char buf[18];
    eth_header = (struct ether_header *)packet;
    printf(
        "Adresse MAC source : %s,",
        ether_ntoa_r((struct ether_addr *)eth_header->ether_shost, buf));
    printf(
        "Adresse MAC destination : %s\n",
        ether_ntoa_r((struct ether_addr *)eth_header->ether_dhost, buf));

    // IP header
    if (htons(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip;
        ip = (struct ip *)(packet + sizeof(struct ether_header));
        printf("IP version : %d, IP Size: %d, Thread size : %d, Protocol "
               ": %d\n"
               "Adresse IP source : %s, Adresse IP destination : %s\n",
               ip->ip_v, ip->ip_hl, ip->ip_len, ip->ip_p,
               inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
    }

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
    // struct bpf_program *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    // bpf_u_int32 netmask;

    if ((handle = pcap_open_live("wlo1", BUFSIZ, 1, 1000, errbuf)) ==
        NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    return 0;
}