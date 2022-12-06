#ifndef SCTP
#define SCTP

#include "../include/include.h"

// Chunk type
#define DATA 0
#define INIT 1
#define INIT_ACK 2
#define SACK 3
#define HEARTBEAT 4
#define HEARTBEAT_ACK 5
#define ABORT 6
#define SHUTDOWN 7
#define SHUTDOWN_ACK 8
#define ERROR 9
#define COOKIE_ECHO 10
#define COOKIE_ACK 11
#define ECNE 12
#define CWR 13
#define SHUTDOWN_COMPLETE 14

struct sctp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t v_tag;
    uint32_t checksum;
};

struct sctp_chunk_hdr {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct sctp_chunk_data {
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_seq;
    uint32_t proto_id;
};

struct sctp_chunk_init {
    uint32_t init_tag;
    uint32_t a_rwnd;
    uint16_t out_streams;
    uint16_t in_streams;
    uint32_t init_tsn;
};

struct sctp_chunk_sack {
    uint32_t cum_tsn_ack;
    uint32_t a_rwnd;
    uint16_t num_gap_ack_blocks;
    uint16_t num_dup_tsns;
};

struct sctp_hdr *sctp_analyzer(const u_char *packet, int length,
                               int verbose);

void sctp_chunk_analyzer(const u_char *packet, int nb_chunks,
                         int length, int verbose);

void get_protocol_sctp(const u_char *packet,
                       struct sctp_hdr *sctp_header, int length,
                       int verbose);

#endif
