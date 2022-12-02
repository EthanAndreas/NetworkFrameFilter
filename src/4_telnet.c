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

    int i = 0;
    while (i < length) {

        if (i % BANNER_LENGTH == 0 && i != 0)
            PRV3(printf("\n"), verbose);

        if (i != length - 2 && packet[i] == 0xff &&
            packet[i + 1] != 0xf0) {
            PRV3(printf("- "), verbose);
            telnet_cmd(packet[i + 1], verbose);
            telnet_opt(packet[i + 2], verbose);
            PRV3(printf("\n"), verbose);
            i += 3;
        }

        else {
            if (isprint(packet[i]))
                PRV3(printf("%c", packet[i]), verbose);
            i++;
        }
    }
    PRV3(printf("\n"), verbose);
}

/**
 * @brief Print the telnet command
 */
void telnet_cmd(const u_char cmd, int verbose) {

    switch (cmd) {
    case 0xf1:
        PRV3(printf("NOP"), verbose);
        break;
    case 0xf2:
        PRV3(printf("DM"), verbose);
        break;
    case 0xf3:
        PRV3(printf("BRK"), verbose);
        break;
    case 0xf4:
        PRV3(printf("IP"), verbose);
        break;
    case 0xf5:
        PRV3(printf("AO"), verbose);
        break;
    case 0xf6:
        PRV3(printf("AYT"), verbose);
        break;
    case 0xf7:
        PRV3(printf("EC"), verbose);
        break;
    case 0xf8:
        PRV3(printf("EL"), verbose);
        break;
    case 0xf9:
        PRV3(printf("GA"), verbose);
        break;
    case 0xfa:
        PRV3(printf("SB"), verbose);
        break;
    case 0xfb:
        PRV3(printf("WILL"), verbose);
        break;
    case 0xfc:
        PRV3(printf("WONT"), verbose);
        break;
    case 0xfd:
        PRV3(printf("DO"), verbose);
        break;
    case 0xfe:
        PRV3(printf("DONT"), verbose);
        break;
    case 0xff:
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
        PRV3(printf(" BINARY"), verbose);
        break;
    case 0x01:
        PRV3(printf(" ECHO"), verbose);
        break;
    case 0x02:
        PRV3(printf(" RCP"), verbose);
        break;
    case 0x03:
        PRV3(printf(" SGA"), verbose);
        break;
    case 0x04:
        PRV3(printf(" NAMS"), verbose);
        break;
    case 0x05:
        PRV3(printf(" STATUS"), verbose);
        break;
    case 0x06:
        PRV3(printf(" TM"), verbose);
        break;
    case 0x07:
        PRV3(printf(" RCTE"), verbose);
        break;
    case 0x08:
        PRV3(printf(" NAOL"), verbose);
        break;
    case 0x09:
        PRV3(printf(" NAOP"), verbose);
        break;
    case 0x0a:
        PRV3(printf(" NAOCRD"), verbose);
        break;
    case 0x0b:
        PRV3(printf(" NAOHTS"), verbose);
        break;
    case 0x0c:
        PRV3(printf(" NAOHTD"), verbose);
        break;
    case 0x0d:
        PRV3(printf(" NAOFFD"), verbose);
        break;
    case 0x0e:
        PRV3(printf(" NAOVTS"), verbose);
        break;
    case 0x0f:
        PRV3(printf(" NAOVTD"), verbose);
        break;
    case 0x10:
        PRV3(printf(" NAOLFD"), verbose);
        break;
    case 0x11:
        PRV3(printf(" XASCII"), verbose);
        break;
    case 0x12:
        PRV3(printf(" LOGOUT"), verbose);
        break;
    case 0x13:
        PRV3(printf(" BM"), verbose);
        break;
    case 0x14:
        PRV3(printf(" DET"), verbose);
        break;
    case 0x15:
        PRV3(printf(" SUPDUP"), verbose);
        break;
    case 0x16:
        PRV3(printf(" SUPDUPOUTPUT"), verbose);
        break;
    case 0x17:
        PRV3(printf(" SNDLOC"), verbose);
        break;
    case 0x18:
        PRV3(printf(" TTYPE"), verbose);
        break;
    case 0x19:
        PRV3(printf(" EOR"), verbose);
        break;
    case 0x1a:
        PRV3(printf(" TUID"), verbose);
        break;
    case 0x1b:
        PRV3(printf(" OUTMRK"), verbose);
        break;
    case 0x1c:
        PRV3(printf(" TTYLOC"), verbose);
        break;
    case 0x1d:
        PRV3(printf(" 3270REGIME"), verbose);
        break;
    case 0x1e:
        PRV3(printf(" X3PAD"), verbose);
        break;
    case 0x1f:
        PRV3(printf(" NAWS"), verbose);
        break;
    case 0x20:
        PRV3(printf(" TSPEED"), verbose);
        break;
    case 0x21:
        PRV3(printf(" LFLOW"), verbose);
        break;
    case 0x22:
        PRV3(printf(" LINEMODE"), verbose);
        break;
    case 0x23:
        PRV3(printf(" XDISPLOC"), verbose);
        break;
    case 0x24:
        PRV3(printf(" OLD_ENVIRON"), verbose);
        break;
    case 0x25:
        PRV3(printf(" AUTHENTICATION"), verbose);
        break;
    case 0x26:
        PRV3(printf(" ENCRYPT"), verbose);
        break;
    case 0x27:
        PRV3(printf(" NEW_ENVIRON"), verbose);
        break;
    case 0x28:
        PRV3(printf(" TN3270E"), verbose);
        break;
    case 0x29:
        PRV3(printf(" XAUTH"), verbose);
        break;
    case 0x2a:
        PRV3(printf(" CHARSET"), verbose);
        break;
    case 0x2b:
        PRV3(printf(" RSP"), verbose);
        break;
    case 0x2c:
        PRV3(printf(" COM_PORT_OPTION"), verbose);
        break;
    case 0x2d:
        PRV3(printf(" SUPPRESS_LOCAL_ECHO"), verbose);
        break;
    case 0x2e:
        PRV3(printf(" TLS"), verbose);
        break;
    case 0x2f:
        PRV3(printf(" KERMIT"), verbose);
        break;
    case 0x30:
        PRV3(printf(" SEND_URL"), verbose);
        break;
    case 0x31:
        PRV3(printf(" FORWARD_X"), verbose);
        break;
    case 0x32:
        PRV3(printf(" PRAGMA_LOGON"), verbose);
        break;
    case 0x33:
        PRV3(printf(" SSPI_LOGON"), verbose);
        break;
    case 0x34:
        PRV3(printf(" PRAGMA_HEARTBEAT"), verbose);
        break;
    case 0x35:
        PRV3(printf(" EXOPL"), verbose);
        break;
    }
}