#include "../include/4_ftp.h"

/**
 * @brief Print informations contained in FTP header
 */
void ftp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    PRV1(printf("FTP"), verbose);

    PRV3(printf("\n" GRN "FTP" NC "\n"), verbose);
}