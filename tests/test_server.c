/* Integration test over a REAL socket: opens the dashboard server on
 * 127.0.0.1, connects to it as a client and exchanges real HTTP.
 * On Windows this exercises the Winsock code (WSAStartup, bind, select,
 * accept, recv, send, closesocket). Run: make test_server
 *
 * One thread only: connecting and sending works before the server calls
 * accept() (the operating system queues the connection), so the test
 * sends a request, lets server_poll() answer it, then reads the reply. */
#ifdef _WIN32
  #include <winsock2.h>
  typedef SOCKET client_socket;
  #define CLOSE_CLIENT closesocket
#else
  #define _POSIX_C_SOURCE 200809L
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int client_socket;
  #define CLOSE_CLIENT close
#endif
#include <stdio.h>
#include <string.h>
#include "../backend/server.h"
#include "../backend/platform.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static App app;
static int port;
static char frontend[64];
static char reply[65536];

static client_socket connect_client(void) {
    struct sockaddr_in address;
    client_socket s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)port);
    connect(s, (struct sockaddr *)&address, sizeof address);
    return s;
}

/* Send raw request bytes, let the server handle them, read the reply. */
static void exchange(const char *request, size_t length) {
    client_socket s = connect_client();
    send(s, request, (int)length, 0);
    server_poll(&app, frontend, 2000);                     /* server answers */
    int total = 0, got;
    while (total < (int)sizeof reply - 1 && (got = recv(s, reply + total, (int)sizeof reply - 1 - total, 0)) > 0)
        total += got;
    reply[total] = '\0';
    CLOSE_CLIENT(s);
}

static void exchange_text(const char *request) { exchange(request, strlen(request)); }

static void http(const char *method, const char *path, const char *body) {
    char request[1024];
    int n = snprintf(request, sizeof request, "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n%s",
                     method, path, (int)strlen(body), body);
    exchange(request, (size_t)n);
}

int main(void) {
    FILE *f = fopen("frontend/index.html", "rb");
    copy_text(frontend, (int)sizeof frontend, f ? "frontend" : "../frontend");
    if (f) fclose(f);

    CHECK(app_init(&app, "data"));
    CHECK(server_startup());
    CHECK(server_open(8085, 20, &port));
    printf("server listening on 127.0.0.1:%d\n", port);

    printf("second server falls back to the next port\n");
    /* Our own listener occupies 'port': a plain bind there must fail. */
    {
        client_socket probe = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((unsigned short)port);
        CHECK(bind(probe, (struct sockaddr *)&a, sizeof a) != 0);
        CLOSE_CLIENT(probe);
    }

    printf("static files\n");
    http("GET", "/", "");
    CHECK(strncmp(reply, "HTTP/1.0 200", 12) == 0 && strstr(reply, "text/html") && strstr(reply, "Login Guard"));
    http("GET", "/css/style.css", "");
    CHECK(strstr(reply, "200 OK") && strstr(reply, "text/css"));
    http("GET", "/missing.html", "");
    CHECK(strstr(reply, "404"));
    http("GET", "/../backend/main.c", "");
    CHECK(strstr(reply, "403"));

    printf("API over the socket\n");
    http("GET", "/api/state", "");
    CHECK(strstr(reply, "200 OK") && strstr(reply, "application/json") && strstr(reply, "\"mode\":\"idle\""));
    http("POST", "/api/simulate", "type=fast&attempts=30&ips=1&autostart=0");
    CHECK(strstr(reply, "200 OK") && strstr(reply, "\"ok\":true"));
    http("POST", "/api/settings", "score=55");
    CHECK(strstr(reply, "Settings saved") && app.detector->settings.score_threshold == 55.0);
    http("PUT", "/api/state", "");
    CHECK(strstr(reply, "405"));

    printf("broken requests do not hurt the server\n");
    exchange_text("POST /api/settings HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n");
    CHECK(strstr(reply, "413"));
    {   /* body shorter than Content-Length, then the client closes */
        client_socket s = connect_client();
        const char *partial = "POST /api/settings HTTP/1.0\r\nContent-Length: 40\r\n\r\nshort=";
        send(s, partial, (int)strlen(partial), 0);
        CLOSE_CLIENT(s);
        server_poll(&app, frontend, 2000);
    }
    exchange_text("garbage\r\n\r\n");
    CHECK(strstr(reply, "400"));
    http("GET", "/api/state", "");                         /* still answering */
    CHECK(strstr(reply, "200 OK"));
    CHECK(server_poll(&app, frontend, 50) == 0);           /* nobody waiting: timeout */

    server_close();
    server_cleanup();
    app_free(&app);
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
