#include "../include/4_pop3.h"

/**
 * @brief Print informations contained in POP3 header
 */
void pop3_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0) {
        PRV1(printf("TCP"), verbose);
        return;
    }

    // One line by frame
    PRV1(printf("POP3"), verbose);

    // One line from the pop3 packet
    PRV2(printf(CYN1 "POP3" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    // Multiple lines from the pop3 packet
    PRV3(printf("\n" GRN "POP3" NC "\n"), verbose);

    int i;
    for (i = 0; i < length; i++) {
        if (i % BANNER_LENGTH == 0 && i != 0)
            PRV3(printf("\n"), verbose);

        if (isprint(packet[i]))
            PRV3(printf("%c", packet[i]), verbose);
        else
            PRV3(printf("."), verbose);
    }

    PRV3(printf("\n"), verbose);
}