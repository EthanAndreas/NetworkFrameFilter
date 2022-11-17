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

// struct dns_name_t {
//     char name[64];
//     int length;
//     int position;
// };

int name_reader(const u_char *packet, int length, int i, int verbose);
void type_print(u_int16_t type, int verbose);
void class_print(u_int16_t class, int verbose);
void rdata_print(u_int16_t type, u_char *rdata, u_int16_t rdlength,
                 int verbose);

int query_parsing(const u_char *packet, int offset, int length,
                  int verbose);
int answer_parsing(const u_char *packet, int offset, int length,
                   int verbose);
int authority_parsing(const u_char *packet, int offset, int length,
                      int verbose);

void dns_analyzer(const u_char *packet, int lenght, int verbose);

#endif