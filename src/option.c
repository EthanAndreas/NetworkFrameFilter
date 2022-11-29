#include "../include/option.h"

void init_usage(usage_t *usage) {

    usage->interface = NULL;
    usage->file = NULL;
    usage->filter = NULL;
    usage->verbose = '3';
}

int option(int argc, char **argv, usage_t *usage) {

    char c;

    while ((c = getopt(argc, argv, "hi:o:v:f:")) != -1) {

        switch (c) {

        case 'h':
            print_option();
            return 1;

        case 'v':
            usage->verbose = optarg[0];
            break;

        case 'i':
            usage->interface = optarg;
            break;

        case 'o':
            usage->file = optarg;
            break;

        case 'f':
            usage->filter = optarg;
            break;

        case '?':
            if (optopt == 'i') {

                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(1);
            } else if (optopt == 'o') {

                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(1);
            } else if (optopt == 'v') {
                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(1);
            } else if (optopt == 'f') {
                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(1);
            } else if (isprint(optopt)) {
                fprintf(stderr,
                        RED "Error"
                            " : Unknown option -%c" NC "\n",
                        optopt);
                print_option();
                exit(1);
            } else {
                fprintf(stderr,
                        RED "Error"
                            " : Unknown option character \\x%x" NC
                            "\n",
                        optopt);
                print_option();
                exit(1);
            }
        }
    }

    return 0;
}

void print_option(void) {

    fprintf(stdout, "Options:\n"
                    "\t-i <file>         interface\n"
                    "\t-o <file>         output\n"
                    "\t-f <nb>           filter\n"
                    "\t-v <nb>           verbose of verbocity\n");
}
