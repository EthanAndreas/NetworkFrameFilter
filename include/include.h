#ifndef INCLUDE_H
#define INCLUDE_H

#include "../include/netinet_bootp.h"
#include <ctype.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#define HTTP2_PORT 443

// Print with verbose level
#define PRV1(op, v)                     \
    do {                                \
        if (v == 1 || v == 2 || v == 3) \
            op;                         \
    } while (0)
#define PRV2(op, v)           \
    do {                      \
        if (v == 2 || v == 3) \
            op;               \
    } while (0)
#define PRV3(op, v) \
    do {            \
        if (v == 3) \
            op;     \
    } while (0)

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

#define COLOR_BANNER                                                 \
    GRN_B "                                                        " \
          "                 " NC

#endif