#include "../include/4_smtp.h"

int intToAscii(int number) { return '0' + number; }

void smtp_analyzer(const u_char *packet, int verbose) {

    printf(GRN "SMTP protocol" NC "\n");

    // int i, size = sizeof(packet);
    // for (i = 0; i < size; i++) {
    //     printf("%0x ", packet[i]);
    // }
    // printf("\n");
}