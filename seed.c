/* Seed binary for the fuzzing round in CI: something small, dynamically
 * linked, and built with the mitigations on, so the mutation corpus starts
 * from a file that exercises every code path in the parser. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[64];
    if (argc > 1) snprintf(buf, sizeof(buf), "%s", argv[1]);
    else          strcpy(buf, "seed");
    puts(buf);
    return 0;
}
