#include "../include/4_telnet.h"

void telnet_analyzer(const u_char *packet, int length, int verbose) {

    // if no data, it is just a tcp/udp packet
    if (length < 1)
        return;

    PRV3(printf(GRN "TELNET" NC "\n"), verbose);
}