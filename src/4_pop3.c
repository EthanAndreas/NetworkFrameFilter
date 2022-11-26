#include "../include/4_pop3.h"

void pop3_analyzer(const u_char *packet, int length, int verbose) {

    // if no data, it is just a tcp/udp packet
    if (length < 1)
        return;

    PRV3(printf(GRN "POP3" NC "\n"), verbose);
}