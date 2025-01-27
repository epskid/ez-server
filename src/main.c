#include "ez.c"
#include "http.c"
#include "server.c"
#include "sys/socket.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>

void Route_hello(Arena *arena, Request *req, Response *resp) {
    resp->status = 200;
    Headers_add(arena, resp->headers, "content-type", "text/html");
    Response_set_body(arena, resp, "<i>Hello, World</i>");
}

void Route_login(Arena *arena, Request *req, Response *resp) {
    Headers_add(arena, resp->headers, "content-type", "text/html");
    LOG_INFO("login attempt -- name is %s", Request_get_param(req, "user"));
    char *cool = Request_get_param(req, "cool");
    LOG_INFO("they are %s", cool);

    if (strcmp(cool, "cool") == 0) {
        resp->status = 200;
        LOG_INFO("user is cool, they can pass");
        Response_set_body(arena, resp, "access granted");
    } else {
        resp->status = 403;
        LOG_INFO("user is uncool, they are denied");
        Response_set_body(arena, resp, "you aren't cool enough");
    }
}

int main(void) {
    Log_initialize(LOG_LEVEL_DEBUG, stderr);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        LOG_FATAL_PERROR("failed to create socket");
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) ==
        -1)
        LOG_PERROR("failed to set socket reuse adress, %d", errno);

    struct sockaddr_in bind_address = {
        .sin_family = AF_INET,
        .sin_port = htons(8000),
        .sin_addr = (struct in_addr){.s_addr = htonl(INADDR_LOOPBACK)}};
    if (bind(sock_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) ==
        -1) {
        LOG_FATAL_PERROR("failed to bind to socket");
    }

    if (listen(sock_fd, 16) == -1) {
        BAIL_PERROR("failed to listen to socket");
    }

    Router *router = Router_new();
    Router_add(router, METHOD_GET, "/hello", Route_hello);
    Router_add(router, METHOD_GET, "/login/:user([a-z]+)/:cool(cool|uncool)",
               Route_login);

    if (start_server(sock_fd, router) == -1) {
        LOG_WARNING("shutting down due to previous error(s)");
    }

    Router_free(router);

    if (close(sock_fd) == -1) {
        LOG_FATAL_PERROR("failed to close socket");
    }

    return EXIT_SUCCESS;
}
