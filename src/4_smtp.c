#include "../include/4_smtp.h"

int intToAscii(int number) { return '0' + number; }

void smtp_analyzer(const u_char *packet, int length, int verbose) {

    // if no data, it is just a tcp/udp packet
    if (length < 1)
        return;

    PRV1(printf(GRN "SMTP protocol" NC "\n"), verbose);

    int i = 0;
    while (packet[i] != 0x0d && packet[i] != 0x0a && i < length) {
        PRV3(printf("%c", packet[i]), verbose);
        i++;
    }
    PRV3(printf("\n"), verbose);
}