#include "../include/4_smtp.h"

/**
 * @brief Print informations contained in SMTP header
 */
void smtp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0) {
        PRV1(printf("TCP"), verbose);
        return;
    }

    // One line by frame
    PRV1(printf("SMTP"), verbose);

    // One line from the smtp packet
    PRV2(printf(CYN1 "SMTP" NC "\t\t"
                     "Length : %d bits",
                length),
         verbose);

    // get the code of the request
    int i, j,
        code = (packet[0] - 48) * 100 + (packet[1] - 48) * 10 +
               (packet[2] - 48);

    if (length > 3) {

        if (code < 0 || code > 999) {
            if ((packet[0] == 0x0d && packet[1] == 0x0a) ||
                packet[0] == '\n') {
                PRV2(printf(", Response : "), verbose);
                for (i = 0; i < length; i++)
                    PRV2(printf("%c", packet[i]), verbose);
            }
            PRV2(printf("\n"), verbose);
        } else
            PRV2(printf(", Code : %d\n", code), verbose);
    } else
        PRV2(printf("\n"), verbose);

    // Multiple lines from the smtp packet
    PRV3(printf("\n" GRN "SMTP protocol" NC "\n"), verbose);

    if (packet[0] == '\r' || packet[0] == '\n') {
        PRV3(printf("\\r\\n\n"), verbose);
        return;
    }

    i = j = 0;
    while (i < length) {

        if (j % BANNER_LENGTH == 0 && j != 0)
            PRV3(printf("\n"), verbose);

        if (i != length && packet[i] == 0x0d &&
            packet[i + 1] == 0x0a) {
            i += 2;
            j = 0;
            PRV3(printf("\n"), verbose);
        }

        if (i < length && isprint(packet[i]))
            PRV3(printf("%c", packet[i]), verbose);
        else {
            if (i < length - 1)
                PRV3(printf("."), verbose);
        }

        i++;
        j++;
    }
}