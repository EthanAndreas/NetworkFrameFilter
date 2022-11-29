#include "../include/4_telnet.h"

/**
 * @brief Print informations contained in TELNET header
 */
void telnet_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    // One line by frame
    PRV1(printf("Telnet"), verbose);

    // One line from the telnet packet
    PRV2(printf(CYN1 "Telnet" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    // Multiple lines from the telnet packet
    PRV3(printf("\n" GRN "TELNET" NC "\n"), verbose);
}