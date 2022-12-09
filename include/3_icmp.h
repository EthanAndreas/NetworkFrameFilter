#ifndef ICMP
#define ICMP

#include "../include/2_ip.h"
#include "../include/include.h"

// ICMP types
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_SOURCE_QUENCH 4
#define ICMP_REDIRECT 5
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAM_PROB 12
#define ICMP_TIMESTAMP 13
#define ICMP_TIMESTAMP_REPLY 14
#define ICMP_INFO_REQUEST 15
#define ICMP_INFO_REPLY 16
#define ICMP_ADDRESS 17
#define ICMP_ADDRESS_REPLY 18

// Unreachable codes
#define ICMP_NET_UNREACH 0
#define ICMP_HOST_UNREACH 1
#define ICMP_PROT_UNREACH 2
#define ICMP_PORT_UNREACH 3
#define ICMP_FRAG_NEEDED 4
#define ICMP_SR_FAILED 5
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13
#define ICMP_PREC_VIOLATION 14
#define ICMP_PREC_CUTOFF 15

// Redirect codes
#define ICMP_REDIR_NET 0
#define ICMP_REDIR_HOST 1
#define ICMP_REDIR_NET_TOS 2
#define ICMP_REDIR_HOST_TOS 3

// Time exceeded codes
#define ICMP_EXC_TTL 0
#define ICMP_EXC_FRAGTIME 1

// Parameter problem codes
#define ICMP_PTR_INDICATES_ERROR 0
#define ICMP_MISSING_REQ_OPTION 1
#define ICMP_BAD_LENGTH 2

#define ICMP_MAX_DATA_SIZE 1024

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
};

struct icmp_packet {
    struct icmp_hdr header;
    uint8_t data[ICMP_MAX_DATA_SIZE];
};

void icmp_analyzer(const u_char *packet, int length, int verbose);

#endif