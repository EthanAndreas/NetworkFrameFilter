#include "../include/2_arp.h"

struct ether_arp *arp_analyzer(const u_char *packet, int verbose) {

    struct ether_arp *arp = (struct ether_arp *)packet;

    PRV1(
        printf("%s\t\t", inet_ntoa(*(struct in_addr *)&arp->arp_spa)),
        verbose);
    PRV1(
        printf("%s\t\t", inet_ntoa(*(struct in_addr *)&arp->arp_tpa)),
        verbose);

    PRV3(printf("\n" GRN "ARP Header" NC "\n"), verbose);

    if (ntohs(arp->arp_hrd) == ARPHRD_ETHER)
        PRV3(printf("Hardware type : Ethernet (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);
    else
        PRV3(printf("Hardware type : Unknown (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);

    if (ntohs(arp->arp_pro) == ETHERTYPE_IP)
        PRV3(printf("Protocol type : IP (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);
    else
        PRV3(printf("Protocol type : Unknown (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);

    PRV3(printf("ARP Hardware size : %d\n"
                "ARP Protocol size : %d\n",
                arp->arp_hln, arp->arp_pln),
         verbose);

    if (ntohs(arp->arp_op) == ARPOP_REQUEST)
        PRV3(printf("Operation : ARP request (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    else if (ntohs(arp->arp_op) == ARPOP_REPLY)
        PRV3(printf("Operation : ARP reply (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    else
        PRV3(printf("Operation : Unknown (%d)\n", ntohs(arp->arp_op)),
             verbose);

    char buf[18];

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