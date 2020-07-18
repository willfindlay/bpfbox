#include <netinet/in.h>

#include "or_die.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Not enough arguments!\n");
        return 1;
    }

    // For tainting
    socket_or_die(AF_INET, SOCK_STREAM, 0);

    if (!strcmp(argv[1], "create-inet6")) {
        socket_or_die(AF_INET6, SOCK_STREAM, 0);
    }

    if (!strcmp(argv[1], "create-unix")) {
        socket_or_die(AF_UNIX, SOCK_STREAM, 0);
    }

    if (!strcmp(argv[1], "inet-create-and-connect")) {
        int fd = socket_or_die(AF_INET6, SOCK_STREAM, 0);

        struct sockaddr_in addr = {};

        addr.sin_family      = AF_INET6;
        addr.sin_port        = htons(8080);
        addr.sin_addr.s_addr = INADDR_ANY;

        connect_or_die(fd, (struct sockaddr *)&addr, sizeof(addr));
    }

    if (!strcmp(argv[1], "create-unix-socketpair")) {
        int socket_vector[2] = {};
        socketpair_or_die(AF_UNIX, SOCK_STREAM, 0, socket_vector);
    }

    return 0;
}
