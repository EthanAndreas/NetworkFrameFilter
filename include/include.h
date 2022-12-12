#ifndef INCLUDE_H
#define INCLUDE_H

#include "../include/netinet_bootp.h"
#include "../include/panic.h"
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// Parameters for pcap_open
#define PROMISC 1
#define TO_MS 1000

// Application protocol
#define DATA_FTP_PORT 20
#define FTP_PORT 21
#define TELNET_PORT 23
#define SMTP_PORT 25
#define DNS_PORT 53
#define BOOTP_PORT 67
#define HTTP_PORT 80
#define POP3_PORT 110
#define IMAP_PORT 143
#define HTTPS_PORT 443

// Print with verbose level
#define PRV1(op, v) \
    do {            \
        if (v == 1) \
            op;     \
    } while (0)
#define PRV2(op, v) \
    do {            \
        if (v == 2) \
            op;     \
    } while (0)
#define PRV3(op, v) \
    do {            \
        if (v >= 3) \
            op;     \
    } while (0)

// Style
// reset
#define NC "\e[0m"
// text color
#define BLU "\e[30m"
#define RED "\e[31m"
#define GRN "\e[32m"
#define YEL "\e[33m"
#define CYN1 "\e[34m"
#define MAG "\e[35m"
#define CYN2 "\e[36m"
#define WHT "\e[37m"
// background color
#define RED_B "\e[41m"
#define GRN_B "\e[42m"
#define ORA_B "\e[43m"
#define CYN1_B "\e[44m"
#define YEL_B "\e[45m"
#define CYN2_B "\e[46m"
#define WHT_B "\e[47m"

#define SIMPLE_BANNER                                                \
    WHT "----------------------------------------------------------" \
        "----"                                                       \
        "--------------------------------------------------" NC

#define COLOR_BANNER                                                 \
    GRN_B "                                                        " \
          "                        " NC
#define BANNER_LENGTH 80

#endif