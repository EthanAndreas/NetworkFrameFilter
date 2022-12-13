#include "../include/4_ftp.h"

/**
 * @brief Print informations contained in FTP header
 */
int ftp_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return 0;

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

    char port_ftp[6];
    int j = 0;
    // if the message begins by "150 Data connection ..." there is a
    // reattribute of the port
    if (length > 40 && packet[0] == '1' && packet[1] == '5' &&
        packet[2] == '0' && packet[3] == ' ' && packet[4] == 'D' &&
        packet[5] == 'a' && packet[6] == 't' && packet[7] == 'a') {

        i = 8;
        while (i < length && packet[i] != ':')
            i++;

        i++;
        while (i < length && packet[i] != ';') {
            port_ftp[j] = packet[i];
            i++;
            j++;
        }

        port_ftp[j] = '\0';

        return atoi(port_ftp);
    }

    return 0;
}