#include "../include/3_icmp.h"

void icmp_analyzer(const u_char *packet, int length, int verbose) {

    // ICMP header
    struct icmp_hdr *icmp_header = (struct icmp_hdr *)packet;

    PRV1(printf("-\t\t\tICMP"), verbose);

    PRV2(printf(MAG "ICMP" NC "\t\t"), verbose);

    PRV3(printf("\n" GRN "ICMP Header" NC "\n"), verbose);

    // ICMP type
    PRV3(printf("ICMP Type : "), verbose);
    switch (icmp_header->type) {
    case ICMP_ECHO_REPLY:
        PRV2(printf("Echo Reply, "), verbose);
        PRV3(printf("Echo Reply\n"), verbose);
        break;
    case ICMP_DEST_UNREACH:
        PRV2(printf("Destination Unreachable, "), verbose);
        PRV3(printf("Destination Unreachable\n"), verbose);
        break;
    case ICMP_SOURCE_QUENCH:
        PRV2(printf("Source Quench, "), verbose);
        PRV3(printf("Source Quench\n"), verbose);
        break;
    case ICMP_REDIRECT:
        PRV2(printf("Redirect, "), verbose);
        PRV3(printf("Redirect\n"), verbose);
        break;
    case ICMP_ECHO:
        PRV2(printf("Echo, "), verbose);
        PRV3(printf("Echo\n"), verbose);
        break;
    case ICMP_TIME_EXCEEDED:
        PRV2(printf("Time Exceeded, "), verbose);
        PRV3(printf("Time Exceeded\n"), verbose);
        break;
    case ICMP_PARAM_PROB:
        PRV2(printf("Parameter Problem, "), verbose);
        PRV3(printf("Parameter Problem\n"), verbose);
        break;
    case ICMP_TIMESTAMP:
        PRV2(printf("Timestamp Request, "), verbose);
        PRV3(printf("Timestamp Request\n"), verbose);
        break;
    case ICMP_TIMESTAMP_REPLY:
        PRV2(printf("Timestamp Reply, "), verbose);
        PRV3(printf("Timestamp Reply\n"), verbose);
        break;
    case ICMP_INFO_REQUEST:
        PRV2(printf("Information Request, "), verbose);
        PRV3(printf("Information Request\n"), verbose);
        break;
    case ICMP_INFO_REPLY:
        PRV2(printf("Information Reply, "), verbose);
        PRV3(printf("Information Reply\n"), verbose);
        break;
    case ICMP_ADDRESS:
        PRV2(printf("Address Mask Request, "), verbose);
        PRV3(printf("Address Mask Request\n"), verbose);
        break;
    case ICMP_ADDRESS_REPLY:
        PRV2(printf("Address Mask Reply, "), verbose);
        PRV3(printf("Address Mask Reply\n"), verbose);
        break;
    }

    // ICMP code
    if (icmp_header->type == ICMP_DEST_UNREACH ||
        icmp_header->type == ICMP_REDIRECT ||
        icmp_header->type == ICMP_TIME_EXCEEDED ||
        icmp_header->type == ICMP_PARAM_PROB)
        PRV3(printf("ICMP Code : "), verbose);
    // Same print as verbose 1 and 2
    verbose++;

    if (icmp_header->type == ICMP_DEST_UNREACH) {

        switch (icmp_header->code) {
        case ICMP_NET_UNREACH:
            PRV3(printf("Network Unreachable\n"), verbose);
            break;
        case ICMP_HOST_UNREACH:
            PRV3(printf("Host Unreachable\n"), verbose);
            break;
        case ICMP_PROT_UNREACH:
            PRV3(printf("Protocol Unreachable\n"), verbose);
            break;
        case ICMP_PORT_UNREACH:
            PRV3(printf("Port Unreachable\n"), verbose);
            break;
        case ICMP_FRAG_NEEDED:
            PRV3(printf("Fragmentation Needed\n"), verbose);
            break;
        case ICMP_SR_FAILED:
            PRV3(printf("Source Route Failed\n"), verbose);
            break;
        case ICMP_NET_UNKNOWN:
            PRV3(printf("Network Unknown\n"), verbose);
            break;
        case ICMP_HOST_UNKNOWN:
            PRV3(printf("Host Unknown\n"), verbose);
            break;
        case ICMP_HOST_ISOLATED:
            PRV3(printf("Host Isolated\n"), verbose);
            break;
        case ICMP_NET_ANO:
            PRV3(printf("Network Administratively Prohibited\n"),
                 verbose);
            break;
        case ICMP_HOST_ANO:
            PRV3(printf("Host Administratively Prohibited\n"),
                 verbose);
            break;
        case ICMP_NET_UNR_TOS:
            PRV3(printf("Network Unreachable for TOS\n"), verbose);
            break;
        case ICMP_HOST_UNR_TOS:
            PRV3(printf("Host Unreachable for TOS\n"), verbose);
            break;
        case ICMP_PKT_FILTERED:
            PRV3(printf("Packet Filtered\n"), verbose);
            break;
        case ICMP_PREC_VIOLATION:
            PRV3(printf("Precedence Violation\n"), verbose);
            break;
        case ICMP_PREC_CUTOFF:
            PRV3(printf("Precedence Cutoff\n"), verbose);
            break;
        }
    }

    if (icmp_header->type == ICMP_REDIRECT) {
        switch (icmp_header->code) {
        case ICMP_REDIR_NET:
            PRV3(printf("Redirect Network\n"), verbose);
            break;
        case ICMP_REDIR_HOST:
            PRV3(printf("Redirect Host\n"), verbose);
            break;
        case ICMP_REDIR_NET_TOS:
            PRV3(printf("Redirect Type of Service and Network\n"),
                 verbose);
            break;
        case ICMP_REDIR_HOST_TOS:
            PRV3(printf("Redirect Type of Service and Host\n"),
                 verbose);
            break;
        }
    }

    if (icmp_header->type == ICMP_TIME_EXCEEDED) {
        switch (icmp_header->code) {
        case ICMP_EXC_TTL:
            PRV3(printf("Time to Live exceeded\n"), verbose);
            break;
        case ICMP_EXC_FRAGTIME:
            PRV3(printf("Fragment Reassembly Time Exceeded\n"),
                 verbose);
            break;
        }
    }

    if (icmp_header->type == ICMP_PARAM_PROB) {
        switch (icmp_header->code) {
        case ICMP_PTR_INDICATES_ERROR:
            PRV3(printf("Pointer indicates the error\n"), verbose);
            break;
        case ICMP_MISSING_REQ_OPTION:
            PRV3(printf("Missing a Required Option\n"), verbose);
            break;
        case ICMP_BAD_LENGTH:
            PRV3(printf("Bad Length\n"), verbose);
            break;
        }
    }
    verbose--;

    // ICMP checksum
    PRV3(printf("ICMP Checksum : 0x%0x (%d)\n", icmp_header->checksum,
                icmp_header->checksum),
         verbose);

    // ICMP echo request/reply, info request/reply, address mask
    // request/reply
    if (icmp_header->type == ICMP_ECHO_REPLY ||
        icmp_header->type == ICMP_INFO_REQUEST ||
        icmp_header->type == ICMP_INFO_REPLY ||
        icmp_header->type == ICMP_ADDRESS ||
        icmp_header->type == ICMP_ADDRESS_REPLY) {

        packet += sizeof(struct icmp_hdr);
        // ICMP identifier
        uint16_t id = ntohs(*(uint16_t *)packet);
        // ICMP sequence number
        uint16_t seq = ntohs(*(uint16_t *)(packet + 2));
        PRV3(printf("ICMP Identifier : %d\n"
                    "ICMP Sequence Number : %d\n",
                    id, seq),
             verbose);
    }

    // Error on IP packet
    else if (icmp_header->type == ICMP_TIME_EXCEEDED ||
             icmp_header->type == ICMP_DEST_UNREACH) {

        packet += sizeof(struct icmp_hdr);

        // IP packet failed
        if (verbose == 1)
            verbose = 0;

        struct iphdr *ip_header = ip_analyzer(packet, verbose);
        if (ip_header == NULL)
            return;
        packet += sizeof(struct iphdr);
        length -= sizeof(struct iphdr);

        get_protocol_ip(packet, ip_header, length, verbose);
    }
}