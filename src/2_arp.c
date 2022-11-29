#include "../include/2_arp.h"

struct ether_arp *arp_analyzer(const u_char *packet, int verbose) {

    struct ether_arp *arp = (struct ether_arp *)packet;
    char buf[18];

    char *src_ip = inet_ntoa(*(struct in_addr *)&arp->arp_spa);
    char *dst_ip = inet_ntoa(*(struct in_addr *)&arp->arp_tpa);

    // One line by frame
    int k;
    for (k = 0; k < strlen(src_ip); k++)
        PRV1(printf("%c", src_ip[k]), verbose);
    for (k = strlen(src_ip); k < 15; k++)
        PRV1(printf(" "), verbose);
    PRV1(printf("\t\t\t\t\t"), verbose);
    for (k = 0; k < strlen(dst_ip); k++)
        PRV1(printf("%c", dst_ip[k]), verbose);
    for (k = strlen(dst_ip); k < 15; k++)
        PRV1(printf(" "), verbose);
    PRV1(printf("\t\t\t\t\t"), verbose);

    // One line from the arp header
    PRV2(printf(YEL "ARP" NC "\t\t"), verbose);

    // Multiple lines from the arp header
    PRV3(printf("\n" GRN "ARP Header" NC "\n"), verbose);

    if (ntohs(arp->arp_hrd) == ARPHRD_ETHER) {
        PRV2(printf("Ethernet (%d), ", ntohs(arp->arp_hrd)), verbose);
        PRV3(printf("Hardware type : Ethernet (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);
    } else
        PRV3(printf("Hardware type : Unknown (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);

    if (ntohs(arp->arp_pro) == ETHERTYPE_IP) {
        PRV2(printf("IPv4 (0x%02x), ", ntohs(arp->arp_pro)), verbose);
        PRV3(printf("Protocol type : IP (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);
    } else
        PRV3(printf("Protocol type : Unknown (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);

    if (ntohs(arp->arp_op) == ARPOP_REQUEST) {
        PRV2(printf("Request (%d), ", ntohs(arp->arp_op)), verbose);
        PRV3(printf("Operation : ARP request (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    } else if (ntohs(arp->arp_op) == ARPOP_REPLY) {
        PRV2(printf("Reply (%d), ", ntohs(arp->arp_op)), verbose);
        PRV3(printf("Operation : ARP reply (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    } else
        PRV3(printf("Operation : Unknown (%d)\n", ntohs(arp->arp_op)),
             verbose);

    PRV2(printf("Hardware size : %d\n", arp->arp_hln), verbose);

    PRV3(printf("ARP Hardware size : %d\n"
                "ARP Protocol size : %d\n",
                arp->arp_hln, arp->arp_pln),
         verbose);

    PRV3(printf(
             "Sender MAC : %s\n",
             addr_mac_print((struct ether_addr *)arp->arp_sha, buf)),
         verbose);

    PRV3(printf("Sender IP address : %s\n",
                inet_ntoa(*(struct in_addr *)arp->arp_spa)),
         verbose);

    PRV3(printf(
             "Target MAC : %s\n",
             addr_mac_print((struct ether_addr *)arp->arp_tha, buf)),
         verbose);

    PRV3(printf("Target IP address : %s\n",
                inet_ntoa(*(struct in_addr *)arp->arp_tpa)),
         verbose);

    return arp;
}