/*
 * server.h - a tiny single-threaded HTTP/1.0 server for the dashboard.
 * Listens on 127.0.0.1 ONLY (other computers cannot connect).
 */
#ifndef SERVER_H
#define SERVER_H

#include "app.h"

#define SERVER_MAX_REQUEST (4 * 1024 * 1024)   /* biggest accepted request (CSV upload) */

/* Starts the network library (WSAStartup on Windows). 1 ok, 0 failed. */
int  server_startup(void);
void server_cleanup(void);                    /* WSACleanup on Windows */

/* Tries first_port, first_port+1, ... (tries ports). Returns 1 and sets
 * *chosen_port on success, 0 if no port could be opened. */
int  server_open(int first_port, int tries, int *chosen_port);
void server_close(void);

/* Waits up to timeout_ms for ONE client, then handles it completely.
 * Returns 1 if a client was handled, 0 on timeout, -1 on error. */
int  server_poll(App *app, const char *frontend_dir, int timeout_ms);

#endif
