#ifndef DNS
#define DNS

#include "../include/include.h"
#include <string.h>

struct dns_hdr {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

struct query_t {
    char qname[64];
    int length;
    int position;
    u_int16_t qtype;
    u_int16_t qclass;
};

struct answer_t {
    char name[64];
    int length;
    int position;
    u_int16_t type;
    u_int16_t class;
    u_int16_t ttl;
    u_int16_t rdlength;
    u_char *rdata;
};

struct authority_t {
    char name[64];
    int length;
    int position;
    u_int16_t type;
    u_int16_t class;
    u_int16_t ttl;
    u_int16_t rdlength;
    u_char *rdata;
};

struct dns_name_t {
    char name[64];
    int length;
    int position;
};

struct dns_name_t name_reader(const u_char *packet, int length,
                              int i);
void type_print(u_int16_t type, int verbose);
void class_print(u_int16_t class, int verbose);
void rdata_print(u_int16_t type, u_char *rdata, u_int16_t rdlength,
                 int verbose);

struct query_t query_parsing(const u_char *packet, int length,
                             int verbose);
struct answer_t answer_parsing(const u_char *packet, int length,
                               int verbose);
struct authority_t authority_parsing(const u_char *packet, int length,
                                     int verbose);

void dns_analyzer(const u_char *packet, int lenght, int verbose);

#endif