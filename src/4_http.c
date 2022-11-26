#include "../include/4_http.h"

void http_analyzer(const u_char *packet, int length, int verbose) {

    // if no data, it is just a tcp/udp packet
    if (length < 1)
        return;

    PRV3(printf(GRN "HTTP" NC "\n"), verbose);

    int i;
    for (i = 0; i < length; i++) {
        PRV3(printf("%c", packet[i]), verbose);
    }

    PRV3(printf("\n"), verbose);
}