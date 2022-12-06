#ifndef TELNET
#define TELNET

#include "../include/include.h"

// Telnet command
#define SE 240
#define NOP 241
#define DM 242
#define BRK 243
#define IP 244
#define AO 245
#define AYT 246
#define EC 247
#define EL 248
#define GA 249
#define SB 250
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254
#define IAC 255

void telnet_analyzer(const u_char *packet, int length, int verbose);

void telnet_cmd(const u_char cmd, int verbose);
void telnet_opt(const u_char opt, int verbose);

#endif

// Credits for option :
// https://www.iana.org/assignments/telnet-options/telnet-options.xhtml