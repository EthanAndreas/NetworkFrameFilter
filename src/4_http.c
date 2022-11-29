#include "../include/4_http.h"

/**
 * @brief Print informations contained in HTTP header
 */
void http_analyzer(const u_char *packet, int port, int length,
                   int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    if (port == HTTP2_PORT) {
        PRV1(printf("HTTP/2 - SSL"), verbose);
        PRV2(
            printf(CYN1 "HTTP/2" NC "\t\tTransport Layer Security\n"),
            verbose);
        PRV3(printf(GRN "HTTP/2" NC "\nTransport Layer Security\n"),
             verbose);
        return;
    }

    if (port != HTTP_PORT)
        return;

    PRV1(printf("HTTP/1.1"), verbose);

    PRV2(printf(CYN1 "HTTP/1.1" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    PRV3(printf("\n" GRN "HTTP/1.1" NC "\n"), verbose);

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