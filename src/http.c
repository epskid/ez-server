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

Headers *Headers_new(Arena *arena) {
    Headers *headers = Arena_allocate(arena, sizeof(Headers));
    headers->headers = Arena_allocate(arena, sizeof(Header));
    headers->headers_len = 0;

    return headers;
}

void Headers_add(Arena *arena, Headers *headers, char *key, char *value) {
    if (headers->headers_len > 0) {
        headers->headers = Arena_reallocate(
            arena, headers->headers, headers->headers_len * sizeof(Header),
            (headers->headers_len + 1) * sizeof(Header));
    }
    Header *new_header = &headers->headers[headers->headers_len];
    new_header->key = Arena_strdup(arena, key);
    new_header->value = Arena_strdup(arena, value);

    headers->headers_len++;
}

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

    char *raw_queries = Arena_strdup(arena, queries_string);
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
    regmatch_t *matches;
    Queries queries;
} Url;

Url Url_parse(Arena *arena, char *url_data) {
    Url url;

    url.raw_url = url_data;
    url.raw_decoded_url = Arena_strdup(arena, url_data);
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
        url.path = Arena_strdup(arena, url.raw_decoded_url);
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
} RawRequest;

RawRequest Request_parse(Arena *request_arena, char *raw_request) {
    RawRequest request;
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
    Headers *headers;
    char *body;
} Response;

Response *Response_new(Arena *arena) {
    Response *resp = Arena_allocate(arena, sizeof(Response));
    resp->status = 0;
    resp->headers = Headers_new(arena);
    resp->body = NULL;

    return resp;
}

void Response_set_body(Arena *arena, Response *response, char *body) {
    response->body = Arena_strdup(arena, body);
}

char *Response_serialize(Arena *arena, Response *response) {
    char *response_data = Arena_allocate(arena, 1024);

    sprintf(response_data, "HTTP/1.1 %d 2ez4me\r\n", response->status);

    for (size_t i = 0; i < response->headers->headers_len; i++) {
        Header header = response->headers->headers[i];
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
    Response *resp = Response_new(arena);
    resp->status = status;
    Headers_add(arena, resp->headers, "content-type", "text/html");
    resp->body = Arena_allocate(arena, 128);

    sprintf(resp->body, "<h1>ez-server</h1><hr/><p>%s</p>", message);

    return Response_serialize(arena, resp);
}
