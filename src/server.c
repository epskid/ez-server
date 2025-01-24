#pragma once
#include "ez.c"
#include "http.c"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef char *(*RouteFunction)(Arena *, Request *, regmatch_t *);

#define ROUTE(name, ...)                                                       \
    char *Route_##name(Arena *arena, Request *request, regmatch_t *matches) {  \
        Response response;                                                     \
        __VA_ARGS__                                                            \
        return Response_serialize(arena, &response);                           \
    }
#define HEADERS(...)                                                           \
    (Headers) {                                                                \
        .headers = (Header[])__VA_ARGS__,                                      \
        .headers_len = sizeof((Header[])__VA_ARGS__) / sizeof(Header)          \
    }
#define ROUTES(...)                                                            \
    (Routes) {                                                                 \
        .routes = (Route[])__VA_ARGS__,                                        \
        .routes_len = sizeof((Route[])__VA_ARGS__) / sizeof(Route)             \
    }

typedef struct {
    Method method;
    char *path;
    size_t nmatches;
    RouteFunction route;
} Route;

typedef struct {
    Route *routes;
    size_t routes_len;
} Routes;

#define NOT_FOUND 1

int Routes_call(Arena *arena, Routes *routes, Request *req, char **response) {
    for (size_t i = 0; i < routes->routes_len; i++) {
        Route route = routes->routes[i];

        if (route.method == req->method) {
            if (route.nmatches > 0) {
                regex_t re;
                int errcode;

                if ((errcode = regcomp(&re, route.path, 0)) != 0) {
                    char *errbuf = Arena_allocate(arena, 64);
                    regerror(errcode, &re, errbuf, 64);
                    BAIL("error compiling regex: %s", errbuf);
                }

                regmatch_t *matches =
                    Arena_allocate(arena, route.nmatches * sizeof(regmatch_t));
                int match_result =
                    regexec(&re, req->url.path, route.nmatches, matches, 0);
                regfree(&re);
                if (match_result == 0) {
                    route.route(arena, req, matches);
                    return EXIT_SUCCESS;
                } else if (match_result == REG_NOMATCH) {
                    continue;
                } else {
                    char *errbuf = Arena_allocate(arena, 64);
                    regerror(errcode, &re, errbuf, 64);
                    BAIL("error while pattern matching path: %s", errbuf);
                }
            } else {
                if (strcmp(route.path, req->url.path) == 0) {
                    *response = route.route(arena, req, NULL);
                    return EXIT_SUCCESS;
                }
            }
        }
    }

    return NOT_FOUND;
}

typedef struct {
    Routes *routes;
    int peer_fd;
} ServerTaskParams;

void server_task(void *params) {
    ServerTaskParams *st_params = params;
    Routes *routes = st_params->routes;
    int peer_fd = st_params->peer_fd;

    Arena request_arena = Arena_new(8192);
    char *request_data = Arena_allocate(&request_arena, 1024);
    read(peer_fd, request_data, 1024);
    LOG_DEBUG("REQUEST:\n========\n%s\n========", request_data);
    if (request_data[1023] != 0) {
        LOG_WARNING("over 1kb of data in request, squashing it");

        char *too_long = Response_new_server_message(
            &request_arena, 413,
            "your request was too chunky. try an emulsifier.");
        write(peer_fd, too_long, strlen(too_long));
    } else {
        Request req = Request_parse(&request_arena, request_data);
        char *serialized = NULL;
        int route = Routes_call(&request_arena, routes, &req, &serialized);
        if (route == EXIT_SUCCESS) {
            write(peer_fd, serialized, strlen(serialized));
        } else if (route == NOT_FOUND) {
            char *not_found =
                Response_new_server_message(&request_arena, 404, "not found");
            write(peer_fd, not_found, strlen(not_found));
        } else if (route == EXIT_FAILURE) {
            LOG_ERROR("failed to resolve route");
            return;
        }
    }

    Arena_free(&request_arena);

    if (close(peer_fd) == -1) {
        LOG_PERROR("failed to close peer socket");
    }
}

bool server_run = true;

void shutdown_server(int sigio) { server_run = false; }

int start_server(int sock_fd, Routes *routes) {
    struct sigaction act = {};

    act.sa_handler = shutdown_server;

    sigaction(SIGINT, &act, 0);
    sigaction(SIGTERM, &act, 0);

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_size = sizeof(peer_addr);

    ThreadPool *pool = ThreadPool_new(8);

    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    for (;;) {
        int peer_fd;
        while (server_run) {
            peer_fd =
                accept(sock_fd, (struct sockaddr *)&peer_addr, &peer_addr_size);

            if (peer_fd == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_PERROR("failed to accept socket connection");
                    break;
                }
            } else if (peer_fd > -1) {
                break;
            }
        }
        if (!server_run) {
            LOG_INFO("kill requested -- exiting");
            break;
        }
        if (peer_fd == -1) {
            BAIL_PERROR("failed to connect to peer");
        }

        ServerTaskParams *params = malloc(sizeof(ServerTaskParams));
        params->routes = routes;
        params->peer_fd = peer_fd;
        Task *task = malloc(sizeof(Task));
        task->task = &server_task;
        task->params = params;

        ThreadPool_run(pool, task);
    }

    ThreadPool_end(pool);

    return EXIT_SUCCESS;
}
