#ifndef PANIC
#define PANIC

// Check if the operation is successful
#define CHK(op)            \
    do {                   \
        if ((op) == -1)    \
            panic(1, #op); \
    } while (0)

#define PCHK(op)           \
    do {                   \
        if ((op) > 0)      \
            panic(1, #op); \
    } while (0)

#define NCHK(op)           \
    do {                   \
        if ((op) < 0)      \
            panic(1, #op); \
    } while (0)

#define SCHK(op)           \
    do {                   \
        if ((op) == NULL)  \
            panic(1, #op); \
    } while (0)

void panic(int syserr, const char *msg, ...);

#endif