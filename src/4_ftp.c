#include "../include/4_ftp.h"

void ftp_analyzer(const u_char *packet, int length, int verbose) {

    // if no data, it is just a tcp/udp packet
    if (length < 1)
        return;

    PRV3(printf(GRN "FTP" NC "\n"), verbose);
}