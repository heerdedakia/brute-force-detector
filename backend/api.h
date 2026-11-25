/*
 * api.h - turns one HTTP request (method, path, body) for /api/... into a
 * JSON response. It knows nothing about sockets, so it can be unit-tested
 * without a network (see tests/test_api.c).
 */
#ifndef API_H
#define API_H

#include "app.h"
#include "json.h"

/* Returns the HTTP status code (200, 400, 404, 405...) and fills response
 * with a JSON body. wall_now is platform_seconds() at request time. */
int api_handle(App *app, const char *method, const char *path, const char *body,
               double wall_now, StrBuf *response);

/* Builds the full dashboard state (the GET /api/state body). */
void api_build_state(const App *app, StrBuf *out);

#endif
