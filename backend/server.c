/*
 * server.c - minimal HTTP server on top of sockets.
 *
 * WINDOWS (Winsock) functions used - explained for the viva:
 *   WSAStartup(MAKEWORD(2,2), &data) : loads the Winsock library, version 2.2.
 *                                      MUST be called before any socket call.
 *   socket(AF_INET, SOCK_STREAM, 0)  : creates a TCP socket (IPv4, stream).
 *   bind(...)                        : attaches the socket to 127.0.0.1:port.
 *                                      127.0.0.1 = this computer only.
 *   listen(socket, backlog)          : start accepting connection requests.
 *   select(...)                      : wait (with a timeout) until a socket is
 *                                      ready. Lets ONE thread both serve
 *                                      requests and keep the simulation moving.
 *   accept(...)                      : take one waiting client connection.
 *   recv(...) / send(...)            : read / write bytes on the connection.
 *   closesocket(s)                   : close a socket (Windows name for close).
 *   WSACleanup()                     : unload Winsock when the program ends.
 * On Linux/macOS the same calls exist (close instead of closesocket, no
 * WSAStartup/WSACleanup), so only a few lines differ - see #ifdef _WIN32.
 *
 * Request handling: read the request line ("GET /path HTTP/1.1") and the
 * headers until the empty line, read Content-Length bytes of body, answer,
 * close the connection ("Connection: close" - one request per connection).
 */
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET socket_t;
  #define CLOSE_SOCKET closesocket
  #define SOCKET_IS_INVALID(s) ((s) == INVALID_SOCKET)
#else
  #define _POSIX_C_SOURCE 200809L
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <signal.h>
  typedef int socket_t;
  #define INVALID_SOCKET (-1)
  #define CLOSE_SOCKET close
  #define SOCKET_IS_INVALID(s) ((s) < 0)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "server.h"
#include "api.h"
#include "json.h"
#include "platform.h"

static socket_t listener = INVALID_SOCKET;

int server_startup(void) {
#ifdef _WIN32
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    signal(SIGPIPE, SIG_IGN);   /* writing to a closed browser tab must not kill us */
    return 1;
#endif
}

void server_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int server_open(int first_port, int tries, int *chosen_port) {
    for (int port = first_port; port < first_port + tries; port++) {
        socket_t s = socket(AF_INET, SOCK_STREAM, 0);
        if (SOCKET_IS_INVALID(s)) return 0;
#ifndef _WIN32
        /* Linux only: allow an immediate restart after closing. Not used on
         * Windows, where SO_REUSEADDR would let two programs share a port. */
        int yes = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes);
#endif
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 127.0.0.1 only */
        address.sin_port = htons((unsigned short)port);      /* network byte order */

        if (bind(s, (struct sockaddr *)&address, sizeof address) == 0 && listen(s, 16) == 0) {
            listener = s;
            *chosen_port = port;
            return 1;
        }
        CLOSE_SOCKET(s);              /* port busy: try the next one */
    }
    return 0;
}

void server_close(void) {
    if (!SOCKET_IS_INVALID(listener)) CLOSE_SOCKET(listener);
    listener = INVALID_SOCKET;
}

/* Wait until s can be read, at most timeout_ms. 1 ready, 0 timeout, -1 error. */
static int wait_readable(socket_t s, int timeout_ms) {
    fd_set read_set;
    struct timeval timeout;
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    /* first argument: highest socket + 1 (ignored by Windows) */
    return select((int)s + 1, &read_set, NULL, NULL, &timeout);
}

/* send() may write only part of the data, so loop until everything is sent. */
static void send_all(socket_t client, const char *data, size_t length) {
    while (length > 0) {
        int chunk = length > 65536 ? 65536 : (int)length;
        int sent = send(client, data, chunk, 0);
        if (sent <= 0) return;                /* browser went away */
        data += sent;
        length -= (size_t)sent;
    }
}

static const char *status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    default:  return "Internal Server Error";
    }
}

static void send_response(socket_t client, int status, const char *content_type,
                          const char *body, size_t body_length) {
    char header[256];
    int n = snprintf(header, sizeof header,
                     "HTTP/1.0 %d %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n"
                     "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
                     status, status_text(status), content_type, (unsigned long)body_length);
    send_all(client, header, (size_t)n);
    if (body_length > 0) send_all(client, body, body_length);
}

static void send_json_error(socket_t client, int status, const char *message) {
    char body[160];
    int n = snprintf(body, sizeof body, "{\"ok\":false,\"error\":\"%s\"}", message);
    send_response(client, status, "application/json", body, (size_t)n);
}

/* ---- static files from frontend/ ---- */

static const char *content_type_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (dot == NULL) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(dot, ".css") == 0)  return "text/css; charset=utf-8";
    if (strcmp(dot, ".js") == 0)   return "application/javascript; charset=utf-8";
    if (strcmp(dot, ".svg") == 0)  return "image/svg+xml";
    if (strcmp(dot, ".png") == 0)  return "image/png";
    if (strcmp(dot, ".ico") == 0)  return "image/x-icon";
    if (strcmp(dot, ".json") == 0) return "application/json";
    return "application/octet-stream";
}

static void serve_file(socket_t client, const char *frontend_dir, const char *url_path) {
    char path[512];
    char clean[256];
    copy_text(clean, (int)sizeof clean, url_path);
    char *query = strchr(clean, '?');
    if (query != NULL) *query = '\0';
    /* Security: refuse anything that tries to climb out of frontend/ */
    if (strstr(clean, "..") != NULL || strchr(clean, '\\') != NULL || strchr(clean, ':') != NULL) {
        send_json_error(client, 403, "forbidden path");
        return;
    }
    if (strcmp(clean, "/") == 0) copy_text(clean, (int)sizeof clean, "/index.html");
    snprintf(path, sizeof path, "%s%s", frontend_dir, clean);

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        send_json_error(client, 404, "file not found");
        return;
    }
    StrBuf content;
    char chunk[8192];
    size_t got;
    sb_init(&content);
    while ((got = fread(chunk, 1, sizeof chunk, file)) > 0) sb_append_bytes(&content, chunk, got);
    fclose(file);
    if (content.failed) send_json_error(client, 500, "out of memory");
    else send_response(client, 200, content_type_for(path), content.data ? content.data : "", content.length);
    sb_free(&content);
}

/* ---- reading one request ---- */

/* Finds "Content-Length:" (any case) in the header block. */
static long content_length_of(const char *headers) {
    const char *p = headers;
    while (*p != '\0') {
        if (tolower((unsigned char)*p) == 'c') {
            const char *name = "content-length:";
            int i = 0;
            while (name[i] != '\0' && tolower((unsigned char)p[i]) == name[i]) i++;
            if (name[i] == '\0') return strtol(p + i, NULL, 10);
        }
        p++;
    }
    return 0;
}

static void handle_client(socket_t client, App *app, const char *frontend_dir) {
    StrBuf request;
    char chunk[8192];
    /* IMPORTANT: we remember WHERE the headers end as a number (an offset),
     * never as a pointer. sb_append_bytes may realloc() the buffer to a new
     * address, and a pointer into the old buffer would then point at freed
     * memory. An offset stays correct wherever the buffer lives. */
    long header_length = -1;     /* bytes before "\r\n\r\n", -1 = not seen yet */
    long body_expected = 0;      /* Content-Length                              */
    long body_received = 0;
    sb_init(&request);

    /* Read until we have the headers AND the whole body (or give up). */
    for (;;) {
        if (wait_readable(client, 3000) <= 0) break;                 /* slow / silent client */
        int got = recv(client, chunk, sizeof chunk, 0);
        if (got <= 0) break;                                          /* client closed */
        sb_append_bytes(&request, chunk, (size_t)got);
        if (request.failed || request.length > SERVER_MAX_REQUEST + 8192) {
            send_json_error(client, 413, "request too large");
            sb_free(&request);
            return;
        }
        if (header_length < 0) {
            char *end = strstr(request.data, "\r\n\r\n");
            if (end != NULL) {
                header_length = (long)(end - request.data);
                *end = '\0';                         /* request.data is now just the headers */
                body_expected = content_length_of(request.data);
                if (body_expected < 0 || body_expected > SERVER_MAX_REQUEST) {
                    send_json_error(client, 413, "request too large");
                    sb_free(&request);
                    return;
                }
            } else if (request.length > 16384) {     /* headers this long are not normal */
                send_json_error(client, 400, "headers too long");
                sb_free(&request);
                return;
            }
        }
        if (header_length >= 0) {
            body_received = (long)request.length - (header_length + 4);
            if (body_received >= body_expected) break;               /* complete */
        }
    }
    if (header_length < 0) {                                          /* never got the headers */
        sb_free(&request);
        return;
    }
    if (body_received < body_expected) {                              /* client stopped early */
        send_json_error(client, 400, "incomplete request body");
        sb_free(&request);
        return;
    }

    /* Request line: METHOD SP PATH SP VERSION */
    char method[8] = "", path[256] = "";
    if (sscanf(request.data, "%7s %255s", method, path) != 2) {
        send_json_error(client, 400, "bad request line");
        sb_free(&request);
        return;
    }
    /* body_expected <= body_received, so this '\0' is inside the data we hold */
    char *body = request.data + header_length + 4;
    body[body_expected] = '\0';

    if (strncmp(path, "/api/", 5) == 0) {
        StrBuf response;
        sb_init(&response);
        int status = api_handle(app, method, path, body, platform_seconds(), &response);
        if (response.failed) send_json_error(client, 500, "out of memory");
        else send_response(client, status, "application/json", response.data ? response.data : "", response.length);
        sb_free(&response);
    } else if (strcmp(method, "GET") == 0) {
        serve_file(client, frontend_dir, path);
    } else {
        send_json_error(client, 405, "method not allowed");
    }
    sb_free(&request);
}

int server_poll(App *app, const char *frontend_dir, int timeout_ms) {
    if (SOCKET_IS_INVALID(listener)) return -1;
    int ready = wait_readable(listener, timeout_ms);
    if (ready <= 0) return ready < 0 ? -1 : 0;
    socket_t client = accept(listener, NULL, NULL);
    if (SOCKET_IS_INVALID(client)) return -1;
    handle_client(client, app, frontend_dir);
    CLOSE_SOCKET(client);
    return 1;
}
