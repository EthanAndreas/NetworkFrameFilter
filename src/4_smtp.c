#include "../include/4_smtp.h"

/**
 * @brief Print informations contained in SMTP header
 */
void smtp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    PRV1(printf("\n" GRN "SMTP protocol" NC "\n"), verbose);

    int i = 0;
    while (packet[i] != 0x0d && packet[i] != 0x0a && i < length) {
        PRV3(printf("%c", packet[i]), verbose);
        i++;
    }
    PRV3(printf("\n"), verbose);
}