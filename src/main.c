#include "ez.c"
#include "http.c"
#include "server.c"
#include "sys/socket.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>

ROUTE(hello, {
    response.status = 200;
    response.headers = HEADERS(1, {{"Content-Type", "text/html"}});
    response.body = "<b>Hello</b>";
})

int main(void) {
    Log_initialize(LOG_LEVEL_DEBUG, stderr);
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        LOG_FATAL_PERROR("failed to create socket");
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) ==
        -1)
        LOG_PERROR("failed to set socket reuse adress");

    if (start_server(sock_fd,
                     &(Routes){.routes = (Route[]){{METHOD_GET, "/hello", 0,
                                                    Route_hello}},
                               .routes_len = 2}) == -1) {
        LOG_WARNING("shutting down due to previous error(s)");
    }

    if (close(sock_fd) == -1) {
        LOG_FATAL_PERROR("failed to close socket");
    }

    return EXIT_SUCCESS;
}
