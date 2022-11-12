#ifndef INCLUDE_H
#define INCLUDE_H

#include "../include/netinet_bootp.h"
#include <ctype.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Application protocol
#define DATA_FTP 20
#define FTP 21
#define NB_SMTP 5
#define SMTP_1 25
#define SMTP_2 465
#define SMTP_3 587
#define SMTP_4 2525
#define SMTP_5 25025
#define DNS_PORT 53
#define BOOTP_PORT 67
#define HTTP_PORT 80

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

#endif

// Lien des assets
// packetlife.net/captures/protocol/