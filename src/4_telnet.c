#include "../include/4_telnet.h"

/**
 * @brief Print informations contained in TELNET header
 */
void telnet_analyzer(const u_char *packet, int length, int verbose) {

    // if there is no data left of a padding empty, it is just a
    // tcp/udp packet
    if (length < 1 || packet[0] == 0)
        return;

    // One line by frame
    PRV1(printf("Telnet"), verbose);

    // One line from the telnet packet
    PRV2(printf(CYN1 "Telnet" NC "\t\t"
                     "Length : %d bits\n",
                length),
         verbose);

    // Multiple lines from the telnet packet
    PRV3(printf("\n" GRN "Telnet" NC "\n"), verbose);

    if (packet[0] == '\r' || packet[0] == '\n') {
        PRV3(printf("\\r\\n\n"), verbose);
        return;
    }

    // check if there is telnet command
    int i = 0, opt = 0;
    while (i < length) {

        if (i != length - 2 && packet[i] == IAC &&
            packet[i + 1] != SE) {
            PRV3(printf("- "), verbose);
            telnet_cmd(packet[i + 1], verbose);
            telnet_opt(packet[i + 2], verbose);
            PRV3(printf("\n"), verbose);
            opt = 1;
        }

        i++;
    }

    // if there is no telnet option, print the frame's content
    if (opt == 0) {
        i = 0;
        while (i < length) {
            if (i % BANNER_LENGTH == 0 && i != 0)
                PRV3(printf("\n"), verbose);

            if (isprint(packet[i]))
                PRV3(printf("%c", packet[i]), verbose);
            else
                PRV3(printf("."), verbose);
            i++;
        }

        PRV3(printf("\n"), verbose);
    }
}

/**
 * @brief Print the telnet command
 */
void telnet_cmd(const u_char cmd, int verbose) {

    switch (cmd) {
    case NOP:
        PRV3(printf("NOP"), verbose);
        break;
    case DM:
        PRV3(printf("DM"), verbose);
        break;
    case BRK:
        PRV3(printf("BRK"), verbose);
        break;
    case IP:
        PRV3(printf("IP"), verbose);
        break;
    case AO:
        PRV3(printf("AO"), verbose);
        break;
    case AYT:
        PRV3(printf("AYT"), verbose);
        break;
    case EC:
        PRV3(printf("EC"), verbose);
        break;
    case EL:
        PRV3(printf("EL"), verbose);
        break;
    case GA:
        PRV3(printf("GA"), verbose);
        break;
    case SB:
        PRV3(printf("SB"), verbose);
        break;
    case WILL:
        PRV3(printf("WILL"), verbose);
        break;
    case WONT:
        PRV3(printf("WONT"), verbose);
        break;
    case DO:
        PRV3(printf("DO"), verbose);
        break;
    case DONT:
        PRV3(printf("DONT"), verbose);
        break;
    case IAC:
        PRV3(printf("IAC"), verbose);
        break;
    }
}

/**
 * @brief Print the telnet option
 */
void telnet_opt(const u_char opt, int verbose) {

    switch (opt) {
    case 0x00:
        PRV3(printf(" Binary"), verbose);
        break;
    case 0x01:
        PRV3(printf(" Echo"), verbose);
        break;
    case 0x02:
        PRV3(printf(" Reconnection"), verbose);
        break;
    case 0x03:
        PRV3(printf(" Suppress Go Ahead"), verbose);
        break;
    case 0x04:
        PRV3(printf(" Approx Message Size Negotiation"), verbose);
        break;
    case 0x05:
        PRV3(printf(" Status"), verbose);
        break;
    case 0x06:
        PRV3(printf(" Timing Mark"), verbose);
        break;
    case 0x07:
        PRV3(printf(" Remote Controlled"), verbose);
        break;
    case 0x08:
        PRV3(printf(" Output Line Width"), verbose);
        break;
    case 0x09:
        PRV3(printf(" Output Page Size"), verbose);
        break;
    case 0x0a:
        PRV3(printf(" Output Carriage-Return Disposition"), verbose);
        break;
    case 0x0b:
        PRV3(printf(" Output Horizontal Tab Stops"), verbose);
        break;
    case 0x0c:
        PRV3(printf(" Output Horizontal Tab Disposition"), verbose);
        break;
    case 0x0d:
        PRV3(printf(" Output Formfeed Disposition"), verbose);
        break;
    case 0x0e:
        PRV3(printf(" Output Vertical Tabstops"), verbose);
        break;
    case 0x0f:
        PRV3(printf(" Output Vertical Tab Disposition"), verbose);
        break;
    case 0x10:
        PRV3(printf(" Output Linefeed Disposition"), verbose);
        break;
    case 0x11:
        PRV3(printf(" Extended ASCII"), verbose);
        break;
    case 0x12:
        PRV3(printf(" Logout"), verbose);
        break;
    case 0x13:
        PRV3(printf(" Byte Macro"), verbose);
        break;
    case 0x14:
        PRV3(printf(" Data Entry Terminal"), verbose);
        break;
    case 0x15:
        PRV3(printf(" SUPDUP"), verbose);
        break;
    case 0x16:
        PRV3(printf(" SUPDUP Output"), verbose);
        break;
    case 0x17:
        PRV3(printf(" Send Location"), verbose);
        break;
    case 0x18:
        PRV3(printf(" Terminal Type"), verbose);
        break;
    case 0x19:
        PRV3(printf(" End of Record"), verbose);
        break;
    case 0x1a:
        PRV3(printf(" TACACS User Identification"), verbose);
        break;
    case 0x1b:
        PRV3(printf(" Output Marking"), verbose);
        break;
    case 0x1c:
        PRV3(printf(" Terminal Location Number"), verbose);
        break;
    case 0x1d:
        PRV3(printf(" Telnet 3270 Regime"), verbose);
        break;
    case 0x1e:
        PRV3(printf(" X.3 PAD"), verbose);
        break;
    case 0x1f:
        PRV3(printf(" Negotiate About Window Size"), verbose);
        break;
    case 0x20:
        PRV3(printf(" Terminal Speed"), verbose);
        break;
    case 0x21:
        PRV3(printf(" Remote Flow Control"), verbose);
        break;
    case 0x22:
        PRV3(printf(" Linemode"), verbose);
        break;
    case 0x23:
        PRV3(printf(" X Display Location"), verbose);
        break;
    case 0x24:
        PRV3(printf(" Environment Option"), verbose);
        break;
    case 0x25:
        PRV3(printf(" Authentication Option"), verbose);
        break;
    case 0x26:
        PRV3(printf(" Encryption Option"), verbose);
        break;
    case 0x27:
        PRV3(printf(" New Environment Option"), verbose);
        break;
    case 0x28:
        PRV3(printf(" TN3270E"), verbose);
        break;
    case 0x29:
        PRV3(printf(" X Auth"), verbose);
        break;
    case 0x2a:
        PRV3(printf(" Charset"), verbose);
        break;
    case 0x2b:
        PRV3(printf(" Telnet Remote Serial Port"), verbose);
        break;
    case 0x2c:
        PRV3(printf(" Com Port Control Option"), verbose);
        break;
    case 0x2d:
        PRV3(printf(" Telnet Suppress Local Echo"), verbose);
        break;
    case 0x2e:
        PRV3(printf(" Telnet Start TLS"), verbose);
        break;
    case 0x2f:
        PRV3(printf(" Kermit"), verbose);
        break;
    case 0x30:
        PRV3(printf(" Send-URL"), verbose);
        break;
    case 0x31:
        PRV3(printf(" Forward X"), verbose);
        break;
    case 0x8a:
        PRV3(printf(" Telopt-Pragma-Logon"), verbose);
        break;
    case 0x8b:
        PRV3(printf(" Telopt-SSPI-Logon"), verbose);
        break;
    case 0x8c:
        PRV3(printf(" Telopt-Pragma-Heartbeat"), verbose);
        break;
    case 0xff:
        PRV3(printf(" Extended-Options-List"), verbose);
        break;
    }
}