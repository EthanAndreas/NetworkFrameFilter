#ifndef TELNET
#define TELNET

#include "../include/include.h"

void telnet_analyzer(const u_char *packet, int length, int verbose);

void telnet_cmd(const u_char cmd, int verbose);
void telnet_opt(const u_char opt, int verbose);

#endif