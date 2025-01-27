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

typedef struct {
    RawRequest *raw;
    char *param_data;
    char **param_names;
    regmatch_t *params;
    size_t nmatches;
} Request;

char *Request_get_param(Request *req, char *key) {
    for (size_t i = 0; i < req->nmatches; i++) {
        if (strcmp(req->param_names[i], key) == 0) {
            regmatch_t match = req->params[i + 1];
            char *param = req->param_data + match.rm_so;
            req->param_data[match.rm_eo] = 0;

            return param;
        }
    }

    return NULL;
}

typedef void (*RouteFunction)(Arena *, Request *, Response *);

typedef struct {
    Method method;
    char *path;
    char *regex_pattern;
    char *param_names_data;
    char **param_names;
    size_t nmatches;
    RouteFunction route;
} Route;

typedef struct {
    Route *routes;
    size_t routes_len;
} Router;

Router *Router_new() {
    Router *router = malloc(sizeof(Router));
    router->routes = malloc(sizeof(Route));
    router->routes_len = 0;

    return router;
}

void Router_add(Router *router, Method method, char *path,
                RouteFunction route) {
    if (router->routes_len > 0) {
        router->routes =
            realloc(router->routes, (router->routes_len + 1) * sizeof(Route));
    }

    memcpy(&router->routes[router->routes_len],
           &(Route){.method = method, .path = path, .route = route},
           sizeof(Route));

    char *regex_pattern = strdup(path);
    char *looking_at = regex_pattern;
    size_t nmatches = 0;
    while ((looking_at = strchr(looking_at + 1, ':')) != NULL) {
        char *regex_start = strchr(looking_at, '(');
        memmove(looking_at, regex_start, strlen(regex_start) + 1);
        int depth = 1;
        char *regex_end = looking_at + 1;
        while (depth > 0) {
            if (*regex_end == '(')
                depth++;
            if (*regex_end == ')')
                depth--;

            regex_end++;
        }
        looking_at = regex_end;

        nmatches++;
    }
    router->routes[router->routes_len].nmatches = nmatches;
    router->routes[router->routes_len].regex_pattern = regex_pattern;

    char **names = malloc(nmatches * sizeof(char *));
    char *names_only = strdup(path);
    looking_at = names_only;
    size_t name = 0;
    while ((looking_at = strchr(looking_at, ':')) != NULL) {
        names[name] = looking_at + 1;
        name++;

        char *lparen = strchr(looking_at, '(');
        *lparen = 0;
        int depth = 1;
        char *regex_end = looking_at + 1;
        while (depth > 0) {
            if (*regex_end == '(')
                depth++;
            if (*regex_end == ')')
                depth--;

            regex_end++;
        }
        looking_at = regex_end;
    }
    router->routes[router->routes_len].param_names_data = names_only;
    router->routes[router->routes_len].param_names = names;

    router->routes_len++;
}

void Router_free(Router *router) {
    for (size_t i = 0; i < router->routes_len; i++) {
        free(router->routes[i].param_names);
        free(router->routes[i].param_names_data);
        free(router->routes[i].regex_pattern);
    }

    free(router->routes);
    free(router);
}

#define NOT_FOUND 1

int Router_call(Arena *arena, Router *router, RawRequest *req,
                char **response_data) {
    for (size_t i = 0; i < router->routes_len; i++) {
        Route route = router->routes[i];

        if (route.method == req->method) {
            if (route.nmatches > 0) {
                regex_t re;
                int errcode;

                if ((errcode = regcomp(&re, route.regex_pattern,
                                       REG_EXTENDED)) != 0) {
                    char *errbuf = Arena_allocate(arena, 64);
                    regerror(errcode, &re, errbuf, 64);
                    BAIL("error compiling regex: %s", errbuf);
                }

                regmatch_t *matches = Arena_allocate(
                    arena, (route.nmatches + 1) * sizeof(regmatch_t));
                int match_result =
                    regexec(&re, req->url.path, route.nmatches + 1, matches, 0);
                if (match_result == 0) {
                    Request matched_req = {
                        .raw = req,
                        .param_data = Arena_strdup(arena, req->url.path),
                        .param_names = route.param_names,
                        .params = matches,
                        .nmatches = route.nmatches,
                    };
                    Response *response = Response_new(arena);
                    route.route(arena, &matched_req, response);
                    *response_data = Response_serialize(arena, response);
                    regfree(&re);
                    return EXIT_SUCCESS;
                } else if (match_result == REG_NOMATCH) {
                    regfree(&re);
                    continue;
                } else {
                    char *errbuf = Arena_allocate(arena, 64);
                    regerror(errcode, &re, errbuf, 64);
                    regfree(&re);
                    BAIL("error while pattern matching path: %s", errbuf);
                }
            } else {
                if (strcmp(route.path, req->url.path) == 0) {
                    Response *response = Response_new(arena);
                    route.route(arena, &(Request){.raw = req}, response);
                    *response_data = Response_serialize(arena, response);
                    return EXIT_SUCCESS;
                }
            }
        }
    }

    return NOT_FOUND;
}

typedef struct {
    Router *routes;
    int peer_fd;
} ServerTaskParams;

void server_task(void *params) {
    ServerTaskParams *st_params = params;
    Router *routes = st_params->routes;
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
        RawRequest req = Request_parse(&request_arena, request_data);
        char *serialized = NULL;
        int route = Router_call(&request_arena, routes, &req, &serialized);
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

int start_server(int sock_fd, Router *router) {
    LOG_INFO("server started");

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
        params->routes = router;
        params->peer_fd = peer_fd;
        Task *task = malloc(sizeof(Task));
        task->task = &server_task;
        task->params = params;

        ThreadPool_run(pool, task);
    }

    ThreadPool_end(pool);

    return EXIT_SUCCESS;
}

int start_server_easy(char *in_addr, short port, Router *router) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        LOG_FATAL_PERROR("failed to create socket");
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) ==
        -1)
        LOG_PERROR("failed to set socket reuse adress, %d", errno);

    struct sockaddr_in bind_address = {.sin_family = AF_INET,
                                       .sin_port = htons(port)};
    inet_pton(AF_INET, in_addr, &bind_address.sin_addr);
    if (bind(sock_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) ==
        -1) {
        LOG_FATAL_PERROR("failed to bind to socket");
    }

    if (listen(sock_fd, 16) == -1) {
        BAIL_PERROR("failed to listen to socket");
    }

    if (start_server(sock_fd, router) == -1) {
        LOG_WARNING("shutting down due to previous error(s)");
    }

    Router_free(router);

    if (close(sock_fd) == -1) {
        LOG_FATAL_PERROR("failed to close socket");
    }

    return EXIT_SUCCESS;
}
