#ifndef OPTION
#define OPTION

#include "include.h"

typedef struct usage_t {

    char *interface;
    char *file;
    char *filter;
    u_char verbose;
} usage_t;

void init_usage(usage_t *usage);

int option(int argc, char **argv, usage_t *usage);

void print_option(void);

#endif