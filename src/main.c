#include "server.c"

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

    Router *router = Router_new();
    Router_add(router, METHOD_GET, "/hello", Route_hello);
    Router_add(router, METHOD_GET, "/login/:user([a-z]+)/:cool(cool|uncool)",
               Route_login);

    return start_server_easy("127.0.0.1", 8000, router);
}
