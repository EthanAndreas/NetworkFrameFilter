#include "../include/4_http.h"

void http_analyzer(const u_char *packet, int verbose) {

    PRV1(printf(GRN "HTTP" NC "\n"), verbose);

    int i = 0;
    while (packet[i] != 0x0d && packet[i] != 0x0a) {
        PRV3(printf("%c", packet[i]), verbose);
        i++;
    }
}