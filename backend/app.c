/*
 * app.c - see app.h.
 */
#include <stdio.h>
#include <string.h>
#include "app.h"

const char *app_mode_name(AppMode mode) {
    switch (mode) {
    case MODE_RUNNING:  return "running";
    case MODE_PAUSED:   return "paused";
    case MODE_FINISHED: return "finished";
    default:            return "idle";
    }
}

static void clear_dashboard_data(App *app) {
    app->live_start = 0;
    app->live_count = 0;
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        app->timeline[i].minute = -1;
        app->timeline[i].attempts = app->timeline[i].failed = app->timeline[i].suspicious = 0;
    }
}

int app_init(App *app, const char *data_dir) {
    Settings defaults;
    memset(app, 0, sizeof *app);
    settings_set_defaults(&defaults);
    app->detector = detector_create(&defaults);
    if (app->detector == NULL) return 0;
    stack_init(&app->undo);
    event_list_init(&app->stream);
    sim_config_defaults(&app->sim_config);
    copy_text(app->data_dir, (int)sizeof app->data_dir, data_dir ? data_dir : "data");
    copy_text(app->source, (int)sizeof app->source, "nothing loaded");
    app->speed = 20.0;
    app->mode = MODE_IDLE;
    clear_dashboard_data(app);
    return 1;
}

void app_free(App *app) {
    detector_destroy(app->detector);
    app->detector = NULL;
    event_list_free(&app->stream);
}

/* ---- dashboard bookkeeping ---- */

static void remember_event(App *app, const LoginEvent *e, const EventResult *r) {
    int slot;
    if (app->live_count < LIVE_EVENT_MAX) {
        slot = (app->live_start + app->live_count) % LIVE_EVENT_MAX;
        app->live_count++;
    } else {                                     /* full: overwrite the oldest */
        slot = app->live_start;
        app->live_start = (app->live_start + 1) % LIVE_EVENT_MAX;
    }
    LiveEvent *le = &app->live[slot];
    le->time = e->timestamp;
    copy_text(le->ip, EVENT_IP_MAX, e->ip);
    copy_text(le->username, EVENT_USER_MAX, e->username);
    le->success = e->success;
    le->blocked = r->blocked;
    le->flags = r->flags;
    le->score = r->score;
    copy_text(le->label, (int)sizeof le->label, r->label);

    long long minute = e->timestamp / 60;
    TimelineBucket *bucket = &app->timeline[minute % TIMELINE_BUCKETS];
    if (bucket->minute != minute) {              /* reuse an old bucket */
        bucket->minute = minute;
        bucket->attempts = bucket->failed = bucket->suspicious = 0;
    }
    bucket->attempts++;
    if (!e->success) bucket->failed++;
    if (r->blocked || r->flags) bucket->suspicious++;
}

const LiveEvent *app_live_get(const App *app, int i) {
    if (i < 0 || i >= app->live_count) return NULL;
    int newest = (app->live_start + app->live_count - 1) % LIVE_EVENT_MAX;
    return &app->live[(newest - i + LIVE_EVENT_MAX) % LIVE_EVENT_MAX];
}

/* ---- replay ---- */

static void rewind_stream(App *app) {
    detector_reset(app->detector);
    clear_dashboard_data(app);
    app->next_index = 0;
    app->clock_fraction = 0.0;
    app->sim_clock = app->stream.count > 0 ? app->stream.items[0].timestamp - 1 : 0;
    app->mode = app->stream.count > 0 ? MODE_PAUSED : MODE_IDLE;
}

void app_step(App *app, double wall_now) {
    double elapsed = wall_now - app->last_wall;
    app->last_wall = wall_now;
    if (app->mode != MODE_RUNNING && app->mode != MODE_FINISHED) return;
    if (elapsed < 0) elapsed = 0;
    if (elapsed > 1.0) elapsed = 1.0;            /* e.g. after a long evaluation */

    /* Once the stream is finished we keep the clock moving (paced like the
     * replay) so that running bans still count down and expire. */
    /* The clock counts whole seconds; keep the leftover fraction for later
     * so that slow speeds still move forward correctly. */
    app->clock_fraction += elapsed * app->speed;
    long long advance = (long long)app->clock_fraction;
    app->clock_fraction -= (double)advance;
    app->sim_clock += advance;

    int processed = 0;
    while (app->next_index < app->stream.count && processed < MAX_EVENTS_PER_STEP &&
           app->stream.items[app->next_index].timestamp <= app->sim_clock) {
        EventResult result;
        const LoginEvent *e = &app->stream.items[app->next_index];
        detector_process(app->detector, e, &result);
        remember_event(app, e, &result);
        app->next_index++;
        processed++;
    }
    if (processed == MAX_EVENTS_PER_STEP && app->next_index < app->stream.count)
        app->sim_clock = app->stream.items[app->next_index].timestamp - 1;   /* catch up next step */
    detector_tick(app->detector, app->sim_clock);
    if (app->next_index >= app->stream.count && app->mode == MODE_RUNNING) app->mode = MODE_FINISHED;
}

void app_start(App *app, double wall_now) {
    if (app->stream.count == 0) return;
    app->mode = MODE_RUNNING;                    /* becomes "finished" again if nothing is left */
    app->last_wall = wall_now;
}

void app_pause(App *app) {
    if (app->mode == MODE_RUNNING || app->mode == MODE_FINISHED) app->mode = MODE_PAUSED;
}

void app_reset(App *app) { rewind_stream(app); }
void app_clear_live(App *app) { app->live_start = 0; app->live_count = 0; }

void app_set_speed(App *app, double speed) {
    if (!(speed >= 0.5)) speed = 0.5;            /* also catches NaN */
    if (speed > 3600.0) speed = 3600.0;
    app->speed = speed;
}

int app_load_simulation(App *app, const SimConfig *config) {
    GroundTruth truth;
    ground_truth_init(&truth);
    int count = sim_generate(config, &app->stream, &truth);
    /* The live dashboard never needs the true labels: free them right away.
     * Only the evaluator (evaluation.c) uses ground truth. */
    ground_truth_free(&truth);
    if (count < 0) {
        event_list_free(&app->stream);
        rewind_stream(app);
        return 0;
    }
    app->sim_config = *config;
    app->source_is_csv = 0;
    snprintf(app->source, sizeof app->source, "Simulation: %s (seed %llu)",
             sim_label_name(config->attack_type), config->seed);
    rewind_stream(app);
    return count;
}

static int finish_csv_load(App *app, int count, const char *name) {
    app->source_is_csv = 1;
    snprintf(app->source, sizeof app->source, "CSV: %.60s", name);
    rewind_stream(app);
    return count;
}

int app_load_csv_file(App *app, const char *path) {
    EventList loaded;
    ParseStats stats = {0, 0, 0, 0, 0};
    event_list_init(&loaded);
    int count = parse_file(path, &loaded, &stats);
    if (count < 0) return -1;                    /* keep the old stream */
    event_list_free(&app->stream);
    app->stream = loaded;                        /* take over the array */
    app->parse_stats = stats;
    const char *name = strrchr(path, '/');
    const char *name2 = strrchr(path, '\\');
    if (name2 > name) name = name2;
    return finish_csv_load(app, count, name ? name + 1 : path);
}

int app_load_csv_text(App *app, const char *text, const char *name) {
    EventList loaded;
    ParseStats stats = {0, 0, 0, 0, 0};
    event_list_init(&loaded);
    int count = parse_text(text, &loaded, &stats);
    event_list_free(&app->stream);
    app->stream = loaded;
    app->parse_stats = stats;
    return finish_csv_load(app, count, name ? name : "uploaded file");
}

void app_set_settings(App *app, const Settings *settings) {
    stack_push(&app->undo, &app->detector->settings);   /* remember the old ones */
    detector_apply_settings(app->detector, settings);
}

int app_undo_settings(App *app) {
    Settings previous;
    if (!stack_pop(&app->undo, &previous)) return 0;
    detector_apply_settings(app->detector, &previous);
    return 1;
}

int app_run_evaluation(App *app, int seeds, int throughput_events) {
    if (seeds < 1) seeds = 1;
    if (seeds > 20) seeds = 20;
    if (throughput_events < 10000) throughput_events = 10000;
    if (throughput_events > 2000000) throughput_events = 2000000;
    return evaluation_run(&app->detector->settings, 1000, seeds, throughput_events, &app->evaluation);
}
