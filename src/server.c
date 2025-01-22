#pragma once
#include "ez.c"
#include "http.c"
#include <arpa/inet.h>
#include <unistd.h>

typedef Response Route(Request);

int start_server(int sock_fd) {
    LOG_TRACE("start_server()");
    struct sockaddr_in bind_address = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = htons(8000),
        .sin_addr = (struct in_addr){.s_addr = htonl(INADDR_LOOPBACK)}};
    if (bind(sock_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) ==
        -1) {
        LOG_FATAL_PERROR("failed to bind to socket");
        return -1;
    }
    LOG_DEBUG("bound socket");

    if (listen(sock_fd, 16) == -1) {
        LOG_PERROR("failed to listen to socket");
        return -1;
    }
    LOG_DEBUG("listening");

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_size = sizeof(peer_addr);

    for (;;) {
        int peer_fd =
            accept(sock_fd, (struct sockaddr *)&peer_addr, &peer_addr_size);
        if (peer_fd == -1) {
            LOG_PERROR("failed to connect to peer");
            return -1;
        }
        LOG_DEBUG("accepted connection");

        Arena request_arena = Arena_new(8192);
        char *request_data = Arena_allocate(&request_arena, 1024);
        read(peer_fd, request_data, 1024);
        if (request_data[1023] != 0) {
            LOG_WARNING("over 1kb of data in request, squashing it");

            char *too_long = Response_new_server_message(
                &request_arena, 413,
                "your request was too chunky. try an emulsifier.");
            write(peer_fd, too_long, strlen(too_long));
        } else {
            LOG_DEBUG(request_data);
            Request req = Request_parse(&request_arena, request_data);
            if (strcmp(req.url.path, "/shutdown") == 0) {
                char *rosebud = Response_new_server_message(
                    &request_arena, 200,
                    "'rosebud' &mdash; ez-server has been shut down");
                write(peer_fd, rosebud, strlen(rosebud));
                Arena_free(&request_arena);
                break;
            } else if (strcmp(req.url.path, "/hello") == 0) {
                char *hello =
                    Arena_allocate(&request_arena, 256 * sizeof(char));
                Query *greeting = Queries_get(&req.url.queries, "hello");
                if (greeting != NULL) {
                    strcat(hello, greeting->value);
                } else {
                    strcat(hello, "Hello");
                }
                strcat(hello, ", ");
                Query *world = Queries_get(&req.url.queries, "world");
                if (world != NULL) {
                    strcat(hello, world->value);
                } else {
                    strcat(hello, "World!");
                }
                write(peer_fd, hello, strlen(hello));
            } else if (strcmp(req.url.path, "/html") == 0) {
                Response resp = (Response){
                    .status = 200,
                    .headers = (Headers){.headers =
                                             (Header[]){
                                                 {"Content-Type", "text/html"},
                                             },
                                         .headers_len = 1},
                    .body = "Hello, <b>HTML</b> World!"};
                char *serialized = Response_serialize(&request_arena, &resp);
                LOG_DEBUG(serialized);
                write(peer_fd, serialized, strlen(serialized));
            } else {
                char *not_found = Response_new_server_message(&request_arena,
                                                              404, "not found");
                write(peer_fd, not_found, strlen(not_found));
            }
        }

        Arena_free(&request_arena);

        if (close(peer_fd) == -1) {
            LOG_PERROR("failed to close peer socket");
            return -1;
        }
    }

    return 0;
}
