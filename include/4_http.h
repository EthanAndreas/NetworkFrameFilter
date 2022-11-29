#ifndef HTTP
#define HTTP

#include "../include/include.h"

void http_analyzer(const u_char *packet, int port, int length,
                   int verbose);

#endif