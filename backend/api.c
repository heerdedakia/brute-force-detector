/*
 * api.c - JSON API used by the dashboard. JavaScript never detects anything:
 * it asks for /api/state and shows what this C code computed.
 *
 *   GET  /api/state              everything the dashboard shows
 *   POST /api/start | pause | reset | clear
 *   POST /api/speed              speed=20
 *   POST /api/simulate           type=fast&attempts=60&ips=1&username=admin&seed=7&users=25
 *   POST /api/load_sample        loads data/sample_auth.log
 *   POST /api/upload             body = raw CSV text (name in ?name=...)
 *   POST /api/settings           short=5&medium=8&long=15&score=60&ban=300 (+ optional weights)
 *   POST /api/settings/undo
 *   POST /api/settings/defaults
 *   POST /api/unblock            ip=1.2.3.4
 *   POST /api/evaluate           seeds=5&events=300000
 */
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "parser.h"

/* ======================= helpers ======================= */

static void add_time_field(StrBuf *out, const char *name, long long epoch) {
    char text[24];
    format_datetime(epoch, text, sizeof text);
    sb_appendf(out, "\"%s\":", name);
    sb_json_string(out, text);
}

static int ok_message(StrBuf *out, const char *message) {
    sb_append(out, "{\"ok\":true,\"message\":");
    sb_json_string(out, message);
    sb_append(out, "}");
    return 200;
}

static int error_message(StrBuf *out, int status, const char *message) {
    sb_append(out, "{\"ok\":false,\"error\":");
    sb_json_string(out, message);
    sb_append(out, "}");
    return status;
}

static void add_category_list(StrBuf *out, int flags) {
    int first = 1;
    sb_append(out, "[");
    for (int bit = 0; bit < CATEGORY_COUNT; bit++) {
        if (!(flags & (1 << bit))) continue;
        if (!first) sb_append(out, ",");
        sb_json_string(out, category_name_of_bit(bit));
        first = 0;
    }
    sb_append(out, "]");
}

/* ======================= state pieces ======================= */

static void add_settings(StrBuf *out, const Settings *s) {
    sb_appendf(out, "{\"short_threshold\":%d,\"medium_threshold\":%d,\"long_threshold\":%d,",
               s->short_threshold, s->medium_threshold, s->long_threshold);
    sb_append(out, "\"score_threshold\":"); sb_json_number(out, s->score_threshold);
    sb_appendf(out, ",\"ban_duration\":%d,\"weights\":{", s->ban_duration);
    sb_append(out, "\"short\":"); sb_json_number(out, s->weight_short);
    sb_append(out, ",\"medium\":"); sb_json_number(out, s->weight_medium);
    sb_append(out, ",\"long\":"); sb_json_number(out, s->weight_long);
    sb_append(out, ",\"username\":"); sb_json_number(out, s->weight_username);
    sb_append(out, ",\"target\":"); sb_json_number(out, s->weight_target);
    sb_append(out, ",\"recent\":"); sb_json_number(out, s->weight_recent);
    sb_appendf(out, "},\"windows\":{\"short\":%d,\"medium\":%d,\"long\":%d}", SHORT_WINDOW, MEDIUM_WINDOW, LONG_WINDOW);
    sb_appendf(out, ",\"fixed\":{\"stuffing_usernames\":%d,\"stuffing_min_failures\":%d,"
               "\"distributed_ips\":%d,\"distributed_min_failures\":%d}}",
               STUFFING_USERNAME_LIMIT, STUFFING_MIN_FAILURES, DISTRIBUTED_IP_LIMIT, DISTRIBUTED_MIN_FAILURES);
}

static void add_ip_object(StrBuf *out, const Detector *d, const IpRecord *rec) {
    sb_append(out, "{\"ip\":"); sb_json_string(out, rec->ip);
    sb_append(out, ",\"score\":"); sb_json_number(out, rec->score);
    sb_append(out, ",\"severity\":"); sb_json_string(out, severity_for_score(rec->score, d->settings.score_threshold));
    sb_append(out, ",\"category\":");
    sb_json_string(out, rec->flags ? category_primary_name(rec->flags)
                                   : rec->ever_flags ? category_primary_name(rec->ever_flags) : "None");
    sb_append(out, ",\"categories\":"); add_category_list(out, rec->flags | rec->ever_flags);
    sb_appendf(out, ",\"short\":%d,\"medium\":%d,\"long\":%d,\"distinct_usernames\":%d,"
               "\"failed\":%d,\"attempts\":%d,\"blocked_attempts\":%d,\"banned\":%s,\"times_banned\":%d}",
               deque_size(rec->short_window), deque_size(rec->medium_window), deque_size(rec->long_window),
               ht_count(rec->failed_usernames), rec->total_failures, rec->total_attempts,
               rec->blocked_attempts, rec->is_banned ? "true" : "false", rec->times_banned);
}

static void add_top(StrBuf *out, const Detector *d) {
    HeapItem top[10];
    int count = detector_top(d, 10, top);
    sb_append(out, "[");
    for (int i = 0; i < count; i++) {
        const IpRecord *rec = detector_get_ip(d, top[i].key);
        if (rec == NULL) continue;
        if (i > 0) sb_append(out, ",");
        add_ip_object(out, d, rec);
    }
    sb_append(out, "]");
}

static void add_blocked(StrBuf *out, const Detector *d) {
    int first = 1;
    sb_append(out, "[");
    /* walk the circular queue from the front (ends soonest) to the rear */
    for (int i = 0; i < cq_size(d->bans); i++) {
        const BanEntry *b = cq_get(d->bans, i);
        if (!b->active) continue;                    /* manually unblocked */
        if (!first) sb_append(out, ",");
        first = 0;
        sb_append(out, "{\"ip\":"); sb_json_string(out, b->ip);
        sb_append(out, ",\"reason\":"); sb_json_string(out, b->reason);
        sb_append(out, ",\"score\":"); sb_json_number(out, b->score);
        sb_append(out, ","); add_time_field(out, "blocked_at", b->blocked_at);
        sb_append(out, ","); add_time_field(out, "expires_at", b->expires_at);
        long long remaining = b->expires_at - d->now;
        sb_appendf(out, ",\"remaining\":%lld,\"duration\":%lld}", remaining > 0 ? remaining : 0,
                   b->expires_at - b->blocked_at);
    }
    sb_append(out, "]");
}

static void add_alerts(StrBuf *out, const Detector *d, int max) {
    int i = 0;
    sb_append(out, "[");
    for (const AlertNode *a = d->alerts->head; a != NULL && i < max; a = a->next, i++) {
        if (i > 0) sb_append(out, ",");
        sb_appendf(out, "{\"id\":%d,", a->id);
        add_time_field(out, "time", a->time);
        sb_append(out, ",\"ip\":"); sb_json_string(out, a->ip);
        sb_append(out, ",\"username\":"); sb_json_string(out, a->username);
        sb_append(out, ",\"category\":"); sb_json_string(out, a->category);
        sb_append(out, ",\"severity\":"); sb_json_string(out, a->severity);
        sb_append(out, ",\"score\":"); sb_json_number(out, a->score);
        sb_append(out, ",\"message\":"); sb_json_string(out, a->message);
        sb_append(out, "}");
    }
    sb_append(out, "]");
}

static void add_events(StrBuf *out, const App *app, int max) {
    sb_append(out, "[");
    for (int i = 0; i < app->live_count && i < max; i++) {
        const LiveEvent *e = app_live_get(app, i);
        if (i > 0) sb_append(out, ",");
        sb_append(out, "{");
        add_time_field(out, "time", e->time);
        sb_append(out, ",\"ip\":"); sb_json_string(out, e->ip);
        sb_append(out, ",\"username\":"); sb_json_string(out, e->username);
        sb_appendf(out, ",\"status\":\"%s\",\"blocked\":%s,", e->success ? "SUCCESS" : "FAILED",
                   e->blocked ? "true" : "false");
        sb_append(out, "\"label\":"); sb_json_string(out, e->label);
        sb_append(out, ",\"score\":"); sb_json_number(out, e->score);
        sb_append(out, "}");
    }
    sb_append(out, "]");
}

static void add_timeline(StrBuf *out, const App *app) {
    /* the last 30 simulated minutes, oldest first */
    long long current = app->sim_clock / 60;
    const char *names[3] = {"attempts", "failed", "suspicious"};
    sb_append(out, "{\"labels\":[");
    for (int k = 29; k >= 0; k--) {
        long long minute = current - k;
        long long seconds_of_day = ((minute * 60) % 86400 + 86400) % 86400;
        sb_appendf(out, "%s\"%02lld:%02lld\"", k == 29 ? "" : ",", seconds_of_day / 3600, seconds_of_day / 60 % 60);
    }
    sb_append(out, "]");
    for (int series = 0; series < 3; series++) {
        sb_appendf(out, ",\"%s\":[", names[series]);
        for (int k = 29; k >= 0; k--) {
            long long minute = current - k;
            const TimelineBucket *b = &app->timeline[((minute % TIMELINE_BUCKETS) + TIMELINE_BUCKETS) % TIMELINE_BUCKETS];
            int value = 0;
            if (b->minute == minute) value = series == 0 ? b->attempts : series == 1 ? b->failed : b->suspicious;
            sb_appendf(out, "%s%d", k == 29 ? "" : ",", value);
        }
        sb_append(out, "]");
    }
    sb_append(out, "}");
}

static void add_evaluation(StrBuf *out, const EvalResults *r) {
    if (!r->valid) { sb_append(out, "null"); return; }
    sb_appendf(out, "{\"runs\":%d,\"events\":%lld,\"seed\":%llu,\"types\":[", r->runs, r->accuracy_events, r->base_seed);
    for (int l = LABEL_FAST; l < LABEL_COUNT; l++) {
        if (l > LABEL_FAST) sb_append(out, ",");
        sb_append(out, "{\"name\":"); sb_json_string(out, sim_label_name(l));
        sb_appendf(out, ",\"ips\":%d,\"proposed_detect\":", r->ip_count[l]);
        sb_json_number(out, eval_rate(r->proposed_detected[l], r->ip_count[l]));
        sb_append(out, ",\"proposed_correct\":"); sb_json_number(out, eval_rate(r->proposed_correct[l], r->ip_count[l]));
        sb_append(out, ",\"proposed_blocked\":"); sb_json_number(out, eval_rate(r->proposed_blocked[l], r->ip_count[l]));
        sb_append(out, ",\"baseline_detect\":"); sb_json_number(out, eval_rate(r->baseline_detected[l], r->ip_count[l]));
        sb_append(out, ",\"proposed_delay\":");
        if (r->proposed_detected[l] > 0) sb_json_number(out, r->proposed_delay[l]); else sb_append(out, "null");
        sb_append(out, ",\"baseline_delay\":");
        if (r->baseline_detected[l] > 0) sb_json_number(out, r->baseline_delay[l]); else sb_append(out, "null");
        sb_append(out, "}");
    }
    sb_appendf(out, "],\"normal_ips\":%d,\"proposed_fp\":", r->ip_count[LABEL_NORMAL]);
    sb_json_number(out, eval_rate(r->proposed_detected[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]));
    sb_append(out, ",\"proposed_fp_blocked\":");
    sb_json_number(out, eval_rate(r->proposed_blocked[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]));
    sb_append(out, ",\"baseline_fp\":");
    sb_json_number(out, eval_rate(r->baseline_detected[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]));
    sb_appendf(out, ",\"throughput_events\":%lld,\"proposed_eps\":", r->throughput_events);
    sb_json_number(out, r->proposed_eps);
    sb_append(out, ",\"baseline_eps\":"); sb_json_number(out, r->baseline_eps);
    sb_append(out, ",\"proposed_seconds\":"); sb_json_number(out, r->proposed_seconds);
    sb_append(out, ",\"baseline_seconds\":"); sb_json_number(out, r->baseline_seconds);
    sb_append(out, ",\"score_threshold\":"); sb_json_number(out, r->settings_used.score_threshold);
    sb_append(out, "}");
}

void api_build_state(const App *app, StrBuf *out) {
    const Detector *d = app->detector;
    char clock_text[24];
    format_datetime(app->sim_clock, clock_text, sizeof clock_text);

    sb_append(out, "{\"mode\":"); sb_json_string(out, app_mode_name(app->mode));
    sb_append(out, ",\"source\":"); sb_json_string(out, app->source);
    sb_append(out, ",\"speed\":"); sb_json_number(out, app->speed);
    sb_append(out, ",\"sim_time\":"); sb_json_string(out, app->stream.count ? clock_text : "");
    sb_appendf(out, ",\"progress\":{\"processed\":%d,\"total\":%d}", app->next_index, app->stream.count);

    sb_appendf(out, ",\"counters\":{\"total_attempts\":%lld,\"failed\":%lld,\"success\":%lld,"
               "\"blocked_events\":%lld,\"active_threats\":%d,\"blocked_ips\":%d,\"total_bans\":%d,"
               "\"tracked_ips\":%d,\"alerts\":%d,\"out_of_order\":%lld,\"bans_dropped\":%d}",
               d->total_events, d->total_failed, d->total_success, d->blocked_events,
               detector_active_threats(d), cq_active_count(d->bans), d->total_bans, ht_count(d->ips),
               d->alerts->next_id - 1, d->out_of_order_events, d->bans_dropped);

    sb_append(out, ",\"categories\":[");
    for (int bit = 0; bit < CATEGORY_COUNT; bit++) {
        if (bit > 0) sb_append(out, ",");
        sb_append(out, "{\"name\":"); sb_json_string(out, category_name_of_bit(bit));
        sb_appendf(out, ",\"ips\":%d}", d->category_counts[bit]);
    }
    sb_appendf(out, "],\"distributed_usernames\":%d", d->distributed_usernames);

    sb_append(out, ",\"timeline\":"); add_timeline(out, app);
    sb_append(out, ",\"top\":"); add_top(out, d);
    sb_append(out, ",\"blocked\":"); add_blocked(out, d);
    sb_append(out, ",\"alerts\":"); add_alerts(out, d, 60);
    sb_append(out, ",\"events\":"); add_events(out, app, 300);
    sb_append(out, ",\"settings\":"); add_settings(out, &d->settings);
    sb_appendf(out, ",\"undo_available\":%d", stack_size(&app->undo));

    const ParseStats *p = &app->parse_stats;
    sb_appendf(out, ",\"parse\":{\"is_csv\":%s,\"lines\":%d,\"events\":%d,\"ignored\":%d,\"malformed\":%d,\"first_bad_line\":%d}",
               app->source_is_csv ? "true" : "false", p->lines_read, p->events_ok, p->ignored, p->malformed, p->first_bad_line);

    const SimConfig *c = &app->sim_config;
    sb_appendf(out, ",\"sim_config\":{\"type\":%d,\"attempts\":%d,\"ips\":%d,\"users\":%d,\"seed\":%llu,\"username\":",
               c->attack_type, c->attempts, c->attacker_ips, c->normal_users, c->seed);
    sb_json_string(out, c->target_username);
    sb_append(out, "},\"evaluation\":"); add_evaluation(out, &app->evaluation);
    sb_append(out, "}");
}

/* ======================= actions ======================= */

static int attack_type_from_text(const char *text) {
    if (strcmp(text, "normal") == 0)      return LABEL_NORMAL;
    if (strcmp(text, "fast") == 0)        return LABEL_FAST;
    if (strcmp(text, "slow") == 0)        return LABEL_SLOW;
    if (strcmp(text, "stuffing") == 0)    return LABEL_STUFFING;
    if (strcmp(text, "distributed") == 0) return LABEL_DISTRIBUTED;
    if (strcmp(text, "mixed") == 0)       return SIM_MIXED;
    return -1;
}

static int handle_simulate(App *app, const char *body, double wall_now, StrBuf *out) {
    SimConfig c;
    char text[48];
    int number;
    sim_config_defaults(&c);
    if (!form_get(body, "type", text, sizeof text) || (c.attack_type = attack_type_from_text(text)) < 0)
        return error_message(out, 400, "type must be normal, fast, slow, stuffing, distributed or mixed");
    if (form_get_int(body, "attempts", &number)) {
        if (number < 1 || number > 5000) return error_message(out, 400, "attempts must be 1..5000");
        c.attempts = number;
    }
    if (form_get_int(body, "ips", &number)) {
        if (number < 1 || number > 500) return error_message(out, 400, "ips must be 1..500");
        c.attacker_ips = number;
    }
    if (form_get_int(body, "users", &number)) {
        if (number < 0 || number > 500) return error_message(out, 400, "users must be 0..500");
        c.normal_users = number;
    }
    if (form_get_int(body, "seed", &number) && number >= 0) c.seed = (unsigned long long)number;
    if (form_get(body, "username", text, sizeof text) && text[0] != '\0') {
        LoginEvent probe;          /* reuse the parser's username rules */
        char line[128];
        snprintf(line, sizeof line, "2026-01-01 00:00:00,1.1.1.1,%s,FAILED", text);
        if (!parse_line(line, &probe)) return error_message(out, 400, "username: 1-32 characters, no spaces");
        copy_text(c.target_username, EVENT_USER_MAX, text);
    }
    if (app_load_simulation(app, &c) < 0) return error_message(out, 500, "out of memory");
    if (!form_get(body, "autostart", text, sizeof text) || strcmp(text, "0") != 0) app_start(app, wall_now);
    sb_appendf(out, "{\"ok\":true,\"events\":%d}", app->stream.count);
    return 200;
}

static int handle_settings(App *app, const char *body, StrBuf *out) {
    Settings s = app->detector->settings;      /* start from the current values */
    form_get_int(body, "short", &s.short_threshold);
    form_get_int(body, "medium", &s.medium_threshold);
    form_get_int(body, "long", &s.long_threshold);
    form_get_double(body, "score", &s.score_threshold);
    form_get_int(body, "ban", &s.ban_duration);
    form_get_double(body, "w_short", &s.weight_short);
    form_get_double(body, "w_medium", &s.weight_medium);
    form_get_double(body, "w_long", &s.weight_long);
    form_get_double(body, "w_username", &s.weight_username);
    form_get_double(body, "w_target", &s.weight_target);
    form_get_double(body, "w_recent", &s.weight_recent);
    int unchanged = settings_validate(&s);
    app_set_settings(app, &s);
    return ok_message(out, unchanged ? "Settings saved" : "Settings saved (some values were adjusted into the allowed range)");
}

int api_handle(App *app, const char *method, const char *path, const char *body,
               double wall_now, StrBuf *out) {
    char text[128];
    if (body == NULL) body = "";
    int is_get = strcmp(method, "GET") == 0;
    int is_post = strcmp(method, "POST") == 0;

    /* strip a query string for matching (only /api/upload uses one) */
    char route[128];
    copy_text(route, (int)sizeof route, path);
    char *query = strchr(route, '?');
    if (query != NULL) *query++ = '\0';

    if (strcmp(route, "/api/state") == 0) {
        if (!is_get) return error_message(out, 405, "use GET");
        api_build_state(app, out);
        return 200;
    }
    if (!is_post) return error_message(out, strncmp(route, "/api/", 5) == 0 ? 405 : 404, "use POST");

    if (strcmp(route, "/api/start") == 0) {
        if (app->stream.count == 0) return error_message(out, 409, "Nothing loaded: start a simulation or load a CSV first");
        app_start(app, wall_now);
        return ok_message(out, "Running");
    }
    if (strcmp(route, "/api/pause") == 0)  { app_pause(app); return ok_message(out, "Paused"); }
    if (strcmp(route, "/api/reset") == 0)  { app_reset(app); return ok_message(out, "Reset: stream rewound, detector cleared"); }
    if (strcmp(route, "/api/clear") == 0)  { app_clear_live(app); return ok_message(out, "Live table cleared"); }
    if (strcmp(route, "/api/speed") == 0) {
        double speed;
        if (!form_get_double(body, "speed", &speed)) return error_message(out, 400, "speed missing");
        app_set_speed(app, speed);
        return ok_message(out, "Speed changed");
    }
    if (strcmp(route, "/api/simulate") == 0) return handle_simulate(app, body, wall_now, out);
    if (strcmp(route, "/api/load_sample") == 0) {
        char path_text[300];
        snprintf(path_text, sizeof path_text, "%s/sample_auth.log", app->data_dir);
        int count = app_load_csv_file(app, path_text);
        if (count < 0) return error_message(out, 404, "data/sample_auth.log not found");
        app_start(app, wall_now);
        sb_appendf(out, "{\"ok\":true,\"events\":%d,\"malformed\":%d}", count, app->parse_stats.malformed);
        return 200;
    }
    if (strcmp(route, "/api/upload") == 0) {
        char name[80] = "uploaded.csv";
        if (query != NULL) form_get(query, "name", name, sizeof name);
        int count = app_load_csv_text(app, body, name);
        if (count == 0) {
            sb_appendf(out, "{\"ok\":false,\"error\":\"No valid events found (%d malformed lines)\"}", app->parse_stats.malformed);
            return 400;
        }
        app_start(app, wall_now);
        sb_appendf(out, "{\"ok\":true,\"events\":%d,\"malformed\":%d}", count, app->parse_stats.malformed);
        return 200;
    }
    if (strcmp(route, "/api/settings") == 0) return handle_settings(app, body, out);
    if (strcmp(route, "/api/settings/undo") == 0) {
        if (!app_undo_settings(app)) return error_message(out, 409, "Nothing to undo");
        return ok_message(out, "Previous settings restored");
    }
    if (strcmp(route, "/api/settings/defaults") == 0) {
        Settings s;
        settings_set_defaults(&s);
        app_set_settings(app, &s);
        return ok_message(out, "Default settings restored");
    }
    if (strcmp(route, "/api/unblock") == 0) {
        if (!form_get(body, "ip", text, sizeof text) || text[0] == '\0') return error_message(out, 400, "ip missing");
        if (!detector_unblock(app->detector, text)) return error_message(out, 404, "That IP is not blocked");
        return ok_message(out, "IP unblocked (simulation only)");
    }
    if (strcmp(route, "/api/evaluate") == 0) {
        int seeds = 5, events = 300000;
        form_get_int(body, "seeds", &seeds);
        form_get_int(body, "events", &events);
        if (!app_run_evaluation(app, seeds, events)) return error_message(out, 500, "Evaluation failed (out of memory?)");
        sb_append(out, "{\"ok\":true,\"evaluation\":");
        add_evaluation(out, &app->evaluation);
        sb_append(out, "}");
        return 200;
    }
    return error_message(out, 404, "Unknown API route");
}
