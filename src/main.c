#include "../include/include.h"

int main(int argc, char **argv) {

    usage_t *usage = malloc(sizeof(usage_t));
    init_usage(usage);

    // Check options

    if (option(argc, argv, usage) == 1)
        return 1;

    pcap_t *handle;
    struct bpf_program *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netmask;

    if ((handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf)) ==
        NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s", errbuf);
        exit(1);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    return 0;
}