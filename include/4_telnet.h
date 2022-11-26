#ifndef TELNET
#define TELNET

#include "../include/include.h"

void telnet_analyzer(const u_char *packet, int length, int verbose);

#endif