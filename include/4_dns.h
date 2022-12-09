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

void dns_analyzer(const u_char *packet, int lenght, int verbose);

int query_parsing(const u_char *packet, int offset, int length,
                  int verbose);
int response_parsing(const u_char *packet, int offset, int length,
                     int verbose);
void data_reader(uint16_t type, const u_char *packet, int offset,
                 uint16_t rdlength, int length, int verbose);

int domain_name_print(const u_char *packet, int i, int length,
                      int verbose);
int name_print(const u_char *packet, int i, int length, int verbose);
void type_print(u_int16_t type, int verbose);
void class_print(u_int16_t class, int verbose);

#endif