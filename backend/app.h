/*
 * app.h - application state shared by the HTTP API: the detector, the event
 * stream being replayed, the simulation clock, and data for the dashboard.
 *
 * The simulation clock: when running, every real second advances the
 * simulation clock by 'speed' seconds, and every event whose timestamp is
 * <= the clock is fed to the detector. At speed 20, a 10-minute attack
 * plays in 30 real seconds. Bans expire on THIS clock, so runs are
 * reproducible and do not depend on how fast the computer is.
 */
#ifndef APP_H
#define APP_H

#include "detector.h"
#include "simulator.h"
#include "evaluation.h"
#include "stack.h"

#define LIVE_EVENT_MAX     400    /* events kept for the Live Monitoring table */
#define TIMELINE_BUCKETS   60     /* one bucket per simulated minute           */
#define MAX_EVENTS_PER_STEP 5000  /* keeps the server responsive               */

typedef struct {
    long long time;
    char ip[EVENT_IP_MAX];
    char username[EVENT_USER_MAX];
    int success;
    int blocked;
    int flags;
    double score;
    char label[32];
} LiveEvent;

typedef struct {
    long long minute;      /* simulated minute number this bucket belongs to */
    int attempts;
    int failed;
    int suspicious;        /* events from flagged or blocked IPs            */
} TimelineBucket;

typedef enum { MODE_IDLE = 0, MODE_RUNNING, MODE_PAUSED, MODE_FINISHED } AppMode;

typedef struct {
    Detector *detector;
    SettingsStack undo;              /* old settings for "Undo"             */

    EventList stream;                /* events waiting to be replayed       */
    int next_index;                  /* first event not yet processed       */
    char source[96];                 /* text shown in the dashboard         */
    SimConfig sim_config;            /* last simulation request             */
    ParseStats parse_stats;          /* last CSV load                        */
    int source_is_csv;

    AppMode mode;
    double speed;                    /* simulated seconds per real second   */
    long long sim_clock;
    double clock_fraction;           /* part of a second not yet added      */
    double last_wall;                /* platform_seconds() of the last step */

    LiveEvent live[LIVE_EVENT_MAX];  /* circular buffer, oldest at live_start */
    int live_start;
    int live_count;
    TimelineBucket timeline[TIMELINE_BUCKETS];

    EvalResults evaluation;          /* valid == 0 until evaluation is run   */
    char data_dir[256];              /* where sample_auth.log lives          */
} App;

int  app_init(App *app, const char *data_dir);   /* 1 ok, 0 out of memory */
void app_free(App *app);

/* Advance the clock and feed due events. Call often (every ~100 ms). */
void app_step(App *app, double wall_now);

void app_start(App *app, double wall_now);
void app_pause(App *app);
void app_reset(App *app);          /* rewind the current stream, clear detector */
void app_clear_live(App *app);     /* clear the Live Monitoring table only      */
void app_set_speed(App *app, double speed);

/* Replace the stream. The detector is reset and the replay starts paused. */
int app_load_simulation(App *app, const SimConfig *config);
int app_load_csv_file(App *app, const char *path);     /* -1 cannot open */
int app_load_csv_text(App *app, const char *text, const char *name);

void app_set_settings(App *app, const Settings *settings);  /* pushes the old ones */
int  app_undo_settings(App *app);                          /* 1 ok, 0 nothing   */

int  app_run_evaluation(App *app, int seeds, int throughput_events);

const LiveEvent *app_live_get(const App *app, int i);      /* 0 = newest */
const char *app_mode_name(AppMode mode);

#endif
