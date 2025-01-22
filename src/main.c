#include "ez.c"
#include "server.c"
#include "sys/socket.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    Log_initialize(LogDebug, stderr);
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        LOG_FATAL_PERROR("failed to create socket");
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) ==
        -1)
        LOG_PERROR("failed to set socket reuse adress");

    if (start_server(sock_fd) == -1) {
        LOG_WARNING("shutting down due to previous error(s)");
    }

    if (close(sock_fd) == -1) {
        LOG_FATAL_PERROR("failed to close socket");
    }

    return 0;
}
