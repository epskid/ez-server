#pragma once
#include "ez.c"
#include <ctype.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HEADER_MAX 32

typedef struct {
    char *key;
    char *value;
} Header;

typedef struct {
    Header *headers;
    size_t headers_len;
} Headers;

Header *Headers_get(Headers *headers, char *key) {
    for (size_t i = 0; i < headers->headers_len; i++) {
        if (strcasecmp(headers->headers[i].key, key)) {
            return &headers->headers[i];
        }
    }

    LOG_DEBUG("header not found: %s", key);

    return NULL;
}

typedef enum { METHOD_GET, METHOD_POST, METHOD_PUT } Method;

#define QUERY_MAX 16

typedef struct {
    char *key;
    char *value;
} Query;

Query Query_parse(char *query_string) {
    Query query;

    char *query_save;

    query.key = strtok_r(query_string, "=", &query_save);
    query.value = strtok_r(NULL, "=", &query_save);

    return query;
}

typedef struct {
    Query *queries;
    size_t queries_len;
} Queries;

Queries Queries_parse(Arena *arena, char *queries_string) {
    Queries queries;

    if (queries_string == NULL) {
        queries.queries = NULL;
        queries.queries_len = 0;
        return queries;
    }

    char *raw_queries = Arena_allocate(arena, strlen(queries_string) + 1);
    strcpy(raw_queries, queries_string);
    queries.queries = Arena_allocate(arena, QUERY_MAX * sizeof(Query));
    queries.queries_len = 0;

    char *queries_save;
    char *query_string = strtok_r(raw_queries, "&", &queries_save);

    while (query_string != NULL) {
        queries.queries[queries.queries_len++] = Query_parse(query_string);
        query_string = strtok_r(NULL, "&", &queries_save);
    }

    return queries;
}

Query *Queries_get(Queries *queries, char *key) {
    for (size_t i = 0; i < queries->queries_len; i++) {
        if (strcmp(queries->queries[i].key, key) == 0) {
            return &queries->queries[i];
        }
    }

    return NULL;
}

typedef struct {
    char *raw_url;
    char *raw_decoded_url;
    char *path;
    Queries queries;
} Url;

Url Url_parse(Arena *arena, char *url_data) {
    Url url;

    url.raw_url = url_data;
    url.raw_decoded_url = Arena_allocate(arena, strlen(url_data) + 1);
    strcpy(url.raw_decoded_url, url_data);

    char *query_location = strchr(url.raw_decoded_url, '?');

    char *url_encoded;

    while ((url_encoded = strchr(url.raw_decoded_url, '%'))) {
        *url_encoded = (char)strtoul(
            (char[]){url_encoded[1], url_encoded[2], 0}, NULL, 16);
        if (*url_encoded == 0) {
            memmove(url_encoded, url_encoded + 3, strlen(url_encoded + 3) + 1);

            if (url_encoded < query_location)
                query_location -= 3;
        } else {
            memmove(url_encoded + 1, url_encoded + 3,
                    strlen(url_encoded + 3) + 1);

            if (url_encoded < query_location)
                query_location -= 2;
        }
    }

    if (query_location != NULL) {
        url.path = Arena_allocate(arena, strlen(url.raw_decoded_url) + 1);
        strcpy(url.path, url.raw_decoded_url);
        url.path[query_location - url.raw_decoded_url] = 0;
        url.queries = Queries_parse(
            arena, url.path + (query_location - url.raw_decoded_url) + 1);
    } else {
        url.path = url.raw_decoded_url;
        url.queries = (Queries){.queries = NULL, .queries_len = 0};
    }

    return url;
}

typedef struct {
    char *raw_request;
    Method method;
    Headers headers;
    Url url;
    char *body;
} Request;

Request Request_parse(Arena *request_arena, char *raw_request) {
    Request request;
    request.raw_request = raw_request;

    char *line_save;
    char *line = strtok_r(raw_request, "\r", &line_save);

    char *token_save;
    char *token = strtok_r(line, " ", &token_save);
    if (strcmp(token, "GET") == 0) {
        request.method = METHOD_GET;
    } else if (strcmp(token, "POST") == 0) {
        request.method = METHOD_POST;
    } else if (strcmp(token, "PUT") == 0) {
        request.method = METHOD_PUT;
    } else {
        request.method = METHOD_GET;
        LOG_WARNING("not a supported message type: %s (using GET instead)",
                    token);
    }
    request.url = Url_parse(request_arena, strtok_r(NULL, " ", &token_save));

    request.headers.headers =
        Arena_allocate(request_arena, sizeof(Header) * HEADER_MAX);
    request.headers.headers_len = 0;
    while ((line = strtok_r(NULL, "\r", &line_save))) {
        char *header_save;

        if (strcmp(line, "\n") == 0) {
            break;
        }
        line += 1;

        Header header;
        header.key = strtok_r(line, ":", &header_save);
        header.value = strtok_r(NULL, ":", &header_save);

        while (isspace(*header.value))
            header.value++;

        request.headers.headers[request.headers.headers_len++] = header;
    }

    request.body = strtok_r(NULL, "\r", &line_save) + 1;

    return request;
}

typedef struct {
    uint16_t status;
    Headers headers;
    char *body;
} Response;

char *Response_serialize(Arena *arena, Response *response) {
    char *response_data = Arena_allocate(arena, 1024);

    sprintf(response_data, "HTTP/1.1 %d 2ez4me\r\n", response->status);

    for (size_t i = 0; i < response->headers.headers_len; i++) {
        Header header = response->headers.headers[i];
        sprintf(response_data + strlen(response_data), "%s: %s\r\n", header.key,
                header.value);
    }

    if (response->body == NULL) {
        response->body = "";
    }
    sprintf(response_data + strlen(response_data), "\r\n%s", response->body);

    LOG_DEBUG("RESPONSE:\n========\n%s\n========", response_data);

    return response_data;
}

char *Response_new_server_message(Arena *arena, uint16_t status,
                                  char *message) {
    Response resp = {
        .status = status,
        .headers =
            (Headers){.headers = (Header[]){{"Content-Type", "text/html"}},
                      .headers_len = 1},
        .body = Arena_allocate(arena, 128 * sizeof(char)),
    };

    sprintf(resp.body, "<h1>ez-server</h1><hr/><p>%s</p>", message);

    return Response_serialize(arena, &resp);
}
