#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define DNS_PORT 53
#define BOOTP_PORT 67

// Lien des assets
// packetlife.net/captures/protocol/