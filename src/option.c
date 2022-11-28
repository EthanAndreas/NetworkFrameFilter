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
                        "\nError"
                        " : Option -%c requires an argument\n",
                        optopt);
                exit(1);
            } else if (optopt == 'o') {

                fprintf(stderr,
                        "\nError"
                        " : Option -%c requires an argument\n",
                        optopt);
                exit(1);
            } else if (optopt == 'v') {

                fprintf(stderr,
                        "\nError"
                        " : Option -%c requires an argument\n",
                        optopt);
                exit(1);
            } else
                fprintf(stderr,
                        "\nError"
                        " : Unknown option character '%x'\n",
                        optopt);

            print_option();
            exit(1);
        }
    }

    return 0;
}

void print_option(void) {

    fprintf(stdout, "\n"
                    "Options:\n"
                    "\t-i FILE         interface\n"
                    "\t-o FILE         output\n"
                    "\t-f              filter\n"
                    "\t-v              verbose of verbocity\n");
}
