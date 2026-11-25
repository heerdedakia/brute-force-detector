/* Integration test: drives the REAL API handler (the same code the browser
 * talks to) without any network. Checks the JSON the dashboard receives.
 * Run: make test_api */
#include <stdio.h>
#include <string.h>
#include "../backend/api.h"
#include "../backend/platform.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static App app;
static StrBuf out;

/* Sends one request; returns the status. The JSON answer is in out.data. */
static int call(const char *method, const char *path, const char *body) {
    sb_free(&out);
    sb_init(&out);
    return api_handle(&app, method, path, body, platform_seconds(), &out);
}

static int has(const char *text) { return out.data != NULL && strstr(out.data, text) != NULL; }

/* Pretend 'seconds' of real time passed, in small steps like the main loop. */
static void run_for(double seconds) {
    for (double t = 0; t < seconds; t += 0.1) {
        app.last_wall -= 0.1;
        app_step(&app, platform_seconds());
    }
}

int main(void) {
    sb_init(&out);
    CHECK(app_init(&app, "data") || app_init(&app, "../data"));
    /* tests may run from the project folder or from tests/ */
    FILE *probe = fopen("data/sample_auth.log", "rb");
    if (probe) fclose(probe); else copy_text(app.data_dir, (int)sizeof app.data_dir, "../data");

    printf("empty state and routing\n");
    CHECK(call("GET", "/api/state", NULL) == 200 && has("\"mode\":\"idle\"") && has("\"evaluation\":null"));
    CHECK(call("POST", "/api/start", "") == 409);                  /* nothing loaded yet */
    CHECK(call("POST", "/api/state", "") == 405);
    CHECK(call("GET", "/api/start", NULL) == 405);
    CHECK(call("POST", "/api/nope", "") == 404);

    printf("fast attack simulation end to end\n");
    CHECK(call("POST", "/api/simulate", "type=fast&attempts=40&ips=1&username=admin&seed=3") == 200);
    CHECK(has("\"ok\":true"));
    CHECK(call("POST", "/api/speed", "speed=60") == 200 && app.speed == 60.0);
    run_for(3.0);                                                  /* 3 real s = 180 simulated s */
    CHECK(call("GET", "/api/state", NULL) == 200);
    CHECK(has("\"mode\":\"running\"") || has("\"mode\":\"finished\""));
    CHECK(has("185.220.0.1"));                                     /* the attacker appears ...   */
    CHECK(has("\"name\":\"Fast brute-force\",\"ips\":1"));         /* ... is classified ...      */
    CHECK(has("\"reason\":\"Fast brute-force\""));                  /* ... and is blocked         */
    CHECK(app.detector->total_bans >= 1);

    printf("unblock through the API\n");
    CHECK(call("POST", "/api/unblock", "ip=185.220.0.1") == 200);
    CHECK(call("POST", "/api/unblock", "ip=185.220.0.1") == 404);  /* not blocked any more */
    CHECK(call("POST", "/api/unblock", "") == 400);

    printf("pause, reset, clear\n");
    CHECK(call("POST", "/api/pause", "") == 200 && app.mode == MODE_PAUSED);
    int processed = app.next_index;
    run_for(1.0);
    CHECK(app.next_index == processed);                            /* paused = no progress */
    CHECK(call("POST", "/api/reset", "") == 200 && app.next_index == 0 && app.detector->total_events == 0);
    CHECK(call("POST", "/api/start", "") == 200 && app.mode == MODE_RUNNING);
    run_for(1.0);
    CHECK(app.live_count > 0);
    CHECK(call("POST", "/api/clear", "") == 200 && app.live_count == 0);

    printf("settings, validation, undo stack\n");
    CHECK(call("POST", "/api/settings", "short=3&medium=6&long=12&score=45&ban=120") == 200);
    CHECK(app.detector->settings.short_threshold == 3 && app.detector->settings.ban_duration == 120);
    CHECK(call("POST", "/api/settings", "short=-4&score=abc") == 200 && has("adjusted"));
    CHECK(app.detector->settings.short_threshold == 1);            /* clamped */
    CHECK(app.detector->settings.score_threshold == 45.0);         /* "abc" ignored */
    CHECK(call("POST", "/api/settings/undo", "") == 200 && app.detector->settings.short_threshold == 3);
    CHECK(call("POST", "/api/settings/undo", "") == 200 && app.detector->settings.short_threshold == 5);
    CHECK(call("POST", "/api/settings/undo", "") == 409);          /* stack empty */
    CHECK(call("POST", "/api/settings/defaults", "") == 200 && app.detector->settings.score_threshold == 60.0);

    printf("bad simulation requests are refused\n");
    CHECK(call("POST", "/api/simulate", "type=evil") == 400);
    CHECK(call("POST", "/api/simulate", "type=fast&attempts=0") == 400);
    CHECK(call("POST", "/api/simulate", "type=fast&ips=100000") == 400);
    CHECK(call("POST", "/api/simulate", "type=fast&username=a%20b") == 400);

    printf("CSV: sample log and upload (with an HTML-looking username)\n");
    CHECK(call("POST", "/api/load_sample", "") == 200 && has("\"malformed\":2"));
    CHECK(call("POST", "/api/upload?name=x.csv",
               "2026-11-20 10:00:00,1.2.3.4,<b>x</b>,FAILED\nbad line\n2026-11-20 10:00:01,1.2.3.4,admin,FAILED\n") == 200);
    CHECK(has("\"events\":2") && has("\"malformed\":1"));
    run_for(2.0);
    CHECK(call("GET", "/api/state", NULL) == 200 && has("<b>x</b>"));  /* JSON keeps it as text; the page escapes it */
    CHECK(call("POST", "/api/upload", "nothing valid here") == 400);

    printf("evaluation through the API (small, real run)\n");
    CHECK(call("POST", "/api/evaluate", "seeds=1&events=10000") == 200);
    CHECK(has("\"name\":\"Low-and-slow\"") && has("\"baseline_delay\":null"));
    CHECK(app.evaluation.valid && app.evaluation.throughput_events == 10000);
    CHECK(call("GET", "/api/state", NULL) == 200 && !has("\"evaluation\":null"));

    app_free(&app);
    sb_free(&out);
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
