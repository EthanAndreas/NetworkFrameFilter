#include "../include/2_arp.h"

struct ether_arp *arp_analyzer(const u_char *packet, int verbose) {

    struct ether_arp *arp = (struct ether_arp *)packet;

    PRV1(printf("\n" GRN "ARP Header" NC "\n"), verbose);

    if (ntohs(arp->arp_hrd) == ARPHRD_ETHER)
        PRV1(printf("Hardware type : Ethernet (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);
    else
        PRV1(printf("Hardware type : Unknown (%d)\n",
                    ntohs(arp->arp_hrd)),
             verbose);

    if (ntohs(arp->arp_pro) == ETHERTYPE_IP)
        PRV1(printf("Protocol type : IP (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);
    else
        PRV1(printf("Protocol type : Unknown (0x%02x)\n",
                    ntohs(arp->arp_pro)),
             verbose);

    PRV2(printf("\tARP Hardware size : %d\n"
                "\tARP Protocol size : %d\n",
                arp->arp_hln, arp->arp_pln),
         verbose);

    if (ntohs(arp->arp_op) == ARPOP_REQUEST)
        PRV2(printf("\tOperation : ARP request (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    else if (ntohs(arp->arp_op) == ARPOP_REPLY)
        PRV2(printf("\tOperation : ARP reply (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);
    else
        PRV2(printf("\tOperation : Unknown (%d)\n",
                    ntohs(arp->arp_op)),
             verbose);

    char buf[18];

    PRV3(printf(
             "\t\tSender MAC : %s\n",
             addr_mac_print((struct ether_addr *)arp->arp_sha, buf)),
         verbose);

    PRV3(printf("\t\tSender IP address : %s\n",
                inet_ntoa(*(struct in_addr *)arp->arp_spa)),
         verbose);

    PRV3(printf(
             "\t\tTarget MAC : %s\n",
             addr_mac_print((struct ether_addr *)arp->arp_tha, buf)),
         verbose);

    PRV3(printf("\t\tTarget IP address : %s\n",
                inet_ntoa(*(struct in_addr *)arp->arp_tpa)),
         verbose);

    return arp;
}