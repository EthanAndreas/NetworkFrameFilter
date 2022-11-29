#include "../include/4_imap.h"

/**
 * @brief Print informations contained in IMAP header
 */
void imap_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    // One line by frame
    PRV1(printf("IMAP"), verbose);

    // One line from the imap packet
    PRV2(printf(CYN1 "IMAP" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    // Multiple lines from the imap packet
    PRV3(printf("\n" GRN "IMAP" NC "\n"), verbose);
}