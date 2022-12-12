#include "../include/4_ftp.h"

/**
 * @brief Print informations contained in FTP header
 */
int ftp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return -1;

    // One line by frame
    PRV1(printf("FTP"), verbose);

    // One line from the ftp packet
    PRV2(printf(CYN1 "FTP" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    // Multiple lines from the ftp packet
    PRV3(printf("\n" GRN "FTP" NC "\n"), verbose);

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

    // get the port delimited by ':' and ';'
    char *port = strstr((char *)packet, ":");
    if (port == NULL)
        return -1;
    port++;

    char *end = strstr(port, ";");
    if (end == NULL)
        return -1;
    *end = '\0';

    return atoi(port);
}