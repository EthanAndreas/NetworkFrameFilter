#include "../include/3_sctp.h"

/**
 * @brief Analyze the sctp header
 */
void sctp_analyzer(const u_char *packet, int length, int verbose) {

    struct sctp_hdr *sctp_header = (struct sctp_hdr *)packet;

    PRV1(printf("%d -> %d\t\t", ntohs(sctp_header->src_port),
                ntohs(sctp_header->dst_port)),
         verbose);

    if (length == sizeof(struct sctp_hdr) ||
        packet[sizeof(struct sctp_hdr)] == 0)
        // One line by frame
        PRV1(printf("SCTP"), verbose);

    // One line from the sctp header
    PRV2(printf(MAG "SCTP" NC "\t\t"
                    "src port : %d, "
                    "dst port : %d, "
                    "Verification tag :0x%0x, "
                    "Checksum : 0x%0x\n",
                ntohs(sctp_header->src_port),
                ntohs(sctp_header->dst_port),
                ntohl(sctp_header->v_tag),
                ntohs(sctp_header->checksum)),
         verbose);

    // Multiple lines from the sctp header
    PRV3(printf("\n" GRN "SCTP Header" NC "\n"
                "Source port : %d\n"
                "Destination port : %d\n"
                "Verification tag : 0x%0x\n"
                "Checksum : 0x%0x\n",
                ntohs(sctp_header->src_port),
                ntohs(sctp_header->dst_port),
                ntohl(sctp_header->v_tag),
                ntohl(sctp_header->checksum)),
         verbose);

    // chunck analyzer
    packet += sizeof(struct sctp_hdr);
    length -= sizeof(struct sctp_hdr);
    int nb_chunks = 0;
    sctp_chunk_analyzer(packet, nb_chunks, length, verbose);
}

/**
 * @brief Analyze all sctp chunk
 */
void sctp_chunk_analyzer(const u_char *packet, int nb_chunks,
                         int length, int verbose) {

    if (length <= 0)
        return;

    nb_chunks++;

    struct sctp_chunk_hdr *sctp_chunk =
        (struct sctp_chunk_hdr *)packet;

    // Multiple lines from the sctp chunk header
    PRV3(printf("Chunk n°%d :\n"
                "- Type : ",
                nb_chunks),
         verbose);

    switch (sctp_chunk->type) {
    case DATA:
        PRV3(printf("Payload data (%d)\n"
                    "- Flags : 0x%0x\n"
                    "- Length : %d\n",
                    sctp_chunk->type, sctp_chunk->flags,
                    ntohs(sctp_chunk->length)),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        struct sctp_chunk_data *sctp_data =
            (struct sctp_chunk_data *)packet;
        PRV3(printf("- TSN : %d\n"
                    "- Stream ID : %d\n"
                    "- Stream sequence number : %d\n"
                    "- Payload protocol identifier : %d\n",
                    ntohl(sctp_data->tsn),
                    ntohs(sctp_data->stream_id),
                    ntohs(sctp_data->stream_seq),
                    ntohs(sctp_data->proto_id)),
             verbose);
        break;

    case INIT:
        PRV3(printf("Initiation (%d)\n", sctp_chunk->type), verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        struct sctp_chunk_init *sctp_init =
            (struct sctp_chunk_init *)packet;
        PRV3(printf("\t- Initiate tag : %d\n"
                    "\t- Advertised receiver window credit : %d\n"
                    "\t- Number of outbound streams : %d\n"
                    "\t- Number of inbound streams : %d\n"
                    "\t- Initial TSN : %d\n",
                    ntohl(sctp_init->init_tag),
                    ntohl(sctp_init->a_rwnd),
                    ntohs(sctp_init->out_streams),
                    ntohs(sctp_init->in_streams),
                    ntohl(sctp_init->init_tsn)),
             verbose);
        break;

    case INIT_ACK:
        PRV3(printf("Initiation acknowledgement(%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        struct sctp_chunk_init *sctp_init_ack =
            (struct sctp_chunk_init *)packet;
        PRV3(printf("\t- Initiate tag : %d\n"
                    "\t- Advertised receiver window credit : %d\n"
                    "\t- Number of outbound streams : %d\n"
                    "\t- Number of inbound streams : %d\n"
                    "\t- Initial TSN : %d\n",
                    ntohl(sctp_init_ack->init_tag),
                    ntohl(sctp_init_ack->a_rwnd),
                    ntohs(sctp_init_ack->out_streams),
                    ntohs(sctp_init_ack->in_streams),
                    ntohl(sctp_init_ack->init_tsn)),
             verbose);
        break;

    case SACK:
        PRV3(printf("Selective acknowledgement (%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        struct sctp_chunk_sack *sctp_sack =
            (struct sctp_chunk_sack *)packet;
        PRV3(printf("\t- Cumulative TSN acknowledgement : %d\n"
                    "\t- Advertised receiver window credit : %d\n"
                    "\t- Number of gap ack blocks : %d\n"
                    "\t- Number of duplicate TSNs : %d\n",
                    ntohl(sctp_sack->cum_tsn_ack),
                    ntohl(sctp_sack->a_rwnd),
                    sctp_sack->num_gap_ack_blocks,
                    sctp_sack->num_dup_tsns),
             verbose);
        break;

    case HEARTBEAT:
        PRV3(printf("Heartbeat request(%d)\n", sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t heartbeat_info = *(uint32_t *)packet;
        PRV3(printf("\t- Heartbeat information : %d\n",
                    ntohl(heartbeat_info)),
             verbose);
        break;

    case HEARTBEAT_ACK:
        PRV3(printf("Heartbeat acknowledgement (%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t heartbeat_ack_info = *(uint32_t *)packet;
        PRV3(printf("\t- Heartbeat information : %d\n",
                    ntohl(heartbeat_ack_info)),
             verbose);
        break;

    case ABORT:
        PRV3(printf("Abort (%d)\n", sctp_chunk->type), verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t abort = *(uint32_t *)packet;
        PRV3(printf("\t- Error cause : %d\n", ntohl(abort)), verbose);
        break;

    case SHUTDOWN:
        PRV3(printf("Shutdown (%d)\n", sctp_chunk->type), verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t sctp_shutdown = *(uint32_t *)packet;
        PRV3(printf("\t- Cumulative TSN acknowledgement : %d\n",
                    ntohl(sctp_shutdown)),
             verbose);
        break;

    case SHUTDOWN_ACK:
        PRV3(printf("Shutdown acknowledgement (%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t sctp_shutdown_ack = *(uint32_t *)packet;
        PRV3(printf("\t- Cumulative TSN acknowledgement : %d\n",
                    ntohl(sctp_shutdown_ack)),
             verbose);
        break;

    case ERROR:
        PRV3(printf("Operation error (%d)\n", sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t error_cause = *(uint32_t *)packet;
        PRV3(printf("\t- Error cause : %d\n", ntohl(error_cause)),
             verbose);
        break;

    case COOKIE_ECHO:
        PRV3(printf("State cookie (%d)\n", sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t cookie = *(uint32_t *)packet;
        PRV3(printf("\t- Cookie : %d\n", ntohl(cookie)), verbose);
        break;

    case COOKIE_ACK:
        PRV3(
            printf("Cookie acknowledgement (%d)\n", sctp_chunk->type),
            verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t cookie_ack = *(uint32_t *)packet;
        PRV3(printf("\t- Cookie : %d\n", ntohl(cookie_ack)), verbose);
        break;

    case ECNE:
        PRV3(printf("Explicit congestion notification echo (%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t ecne = *(uint32_t *)packet;
        PRV3(printf("\t- ECNE : %d\n", ntohl(ecne)), verbose);
        break;

    case CWR:
        PRV3(printf("Congestion window reduced (%d)\n",
                    sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t cwr = *(uint32_t *)packet;
        PRV3(printf("\t- CWR : %d\n", ntohl(cwr)), verbose);
        break;

    case SHUTDOWN_COMPLETE:
        PRV3(printf("Shutdown complete (%d)\n", sctp_chunk->type),
             verbose);
        packet += sizeof(struct sctp_chunk_hdr);
        uint32_t shutdown_complete = *(uint32_t *)packet;
        PRV3(printf("\t- Cumulative TSN acknowledgement : %d\n",
                    ntohl(shutdown_complete)),
             verbose);
        break;
    }

    packet += sctp_chunk->length - sizeof(struct sctp_chunk_hdr);
    length -= sctp_chunk->length;
    sctp_chunk_analyzer(packet, nb_chunks, length, verbose);
}