#include "../include/option.h"

void init_usage(usage_t *usage) {

    usage->interface = NULL;
    usage->file = NULL;
    usage->filter = NULL;
    usage->verbose = "1";
}

int option(int argc, char **argv, usage_t *usage) {

    char c;

    while ((c = getopt(argc, argv, "hi:o:v:f:")) != -1) {

        switch (c) {

        case 'h':
            print_option();
            return 1;

        case 'v':
            usage->verbose = optarg;
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
                exit(EXIT_FAILURE);
            } else if (optopt == 'o') {
                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(EXIT_FAILURE);
            } else if (optopt == 'v') {
                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(EXIT_FAILURE);
            } else if (optopt == 'f') {
                fprintf(stderr,
                        RED "Error"
                            " : Option -%c requires an argument" NC
                            "\n",
                        optopt);
                print_option();
                exit(EXIT_FAILURE);
            } else if (isprint(optopt)) {
                fprintf(stderr,
                        RED "Error"
                            " : Unknown option -%c" NC "\n",
                        optopt);
                print_option();
                exit(EXIT_FAILURE);
            } else {
                fprintf(stderr,
                        RED "Error"
                            " : Unknown option character" NC "\n");
                print_option();
                exit(EXIT_FAILURE);
            }
        }

        if (usage->interface == NULL && usage->file == NULL) {
            fprintf(stderr,
                    RED "Error"
                        " : Option -i or -o is required" NC "\n");
            print_option();
            exit(EXIT_FAILURE);
        } else if (usage->interface != NULL && usage->file != NULL) {
            fprintf(stderr,
                    RED "Error"
                        " : You must chose between online and "
                        "offline listening" NC "\n");
            print_option();
            exit(EXIT_FAILURE);
        } else if ((usage->filter != NULL &&
                    usage->interface == NULL) ||
                   (usage->filter != NULL && usage->file != NULL)) {
            fprintf(stderr, RED
                    "Error"
                    " : Filter must be used on online listening" NC
                    "\n");
            print_option();
            exit(EXIT_FAILURE);
        }
    }

    return EXIT_SUCCESS;
}

void print_option(void) {

    fprintf(stdout, "Options:\n"
                    "\t-i <file>         interface\n"
                    "\t-o <file>         output\n"
                    "\t-f <nb>           filter\n"
                    "\t-v <nb>           verbose of verbocity\n");
}
