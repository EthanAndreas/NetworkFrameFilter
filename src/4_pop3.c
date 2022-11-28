#include "../include/4_pop3.h"

/**
 * @brief Print informations contained in POP3 header
 */
void pop3_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    PRV1(printf("POP3"), verbose);

    PRV3(printf("\n" GRN "POP3" NC "\n"), verbose);
}