#include "or_die.h"

int main(int argc, char **argv)
{
    int fd;
    printf("Hello silly program world!\n");

    // For taint
    fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);

    // Test an fs rule
    fd = open_or_die("/tmp/bpfbox/b", O_RDONLY);

    return 0;
}
