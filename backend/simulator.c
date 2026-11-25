/*
 * simulator.c - see simulator.h.
 *
 * How a stream is built:
 *   1. background traffic of normal users is appended,
 *   2. the attack events are appended,
 *   3. everything is sorted by timestamp with a hand-written MERGE SORT
 *      (stable, O(n log n)) that moves each event together with its label.
 *
 * IP ranges are kept apart so that one IP always has ONE true label:
 *   normal 10.x.x.x | fast 185.220.x.x | slow 45.83.x.x
 *   stuffing 91.240.x.x | distributed 198.51.x.x
 * (All of them are made-up addresses for simulation only.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simulator.h"

/* ======================= random numbers ======================= */

void rng_seed(Rng *rng, unsigned long long seed) {
    rng->state = seed != 0 ? seed : 0x9E3779B97F4A7C15ULL;   /* state must not be 0 */
}

/* xorshift64*: three shift/xor steps, then a multiply. Same result on every
 * compiler and operating system because it only uses 64-bit integer math. */
unsigned int rng_next(Rng *rng) {
    unsigned long long x = rng->state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng->state = x;
    return (unsigned int)((x * 0x2545F4914F6CDD1DULL) >> 32);
}

int rng_range(Rng *rng, int low, int high) {
    if (high <= low) return low;
    return low + (int)(rng_next(rng) % (unsigned int)(high - low + 1));
}

/* ======================= names and config ======================= */

static const char *LABEL_NAMES[LABEL_COUNT] = {
    "Normal", "Fast brute-force", "Low-and-slow", "Credential stuffing", "Distributed attack"
};

const char *sim_label_name(int label) {
    if (label == SIM_MIXED) return "Mixed (all attacks)";
    return (label >= 0 && label < LABEL_COUNT) ? LABEL_NAMES[label] : "Unknown";
}

void sim_config_defaults(SimConfig *config) {
    memset(config, 0, sizeof *config);
    config->attack_type = LABEL_FAST;
    config->attempts = 60;
    config->attacker_ips = 1;
    strcpy(config->target_username, "admin");
    config->normal_users = 25;
    config->include_office_nat = 1;
    config->background_seconds = 1800;
    config->start_time = 1795132800LL;     /* 2026-11-20 00:00:00 */
    config->seed = 2026;
}

/* Common usernames a fast bot cycles through. */
static const char *COMMON_NAMES[] = {"admin", "root", "test", "user", "guest", "oracle", "ubuntu", "support"};
#define COMMON_NAME_COUNT 8

/* ======================= stream building ======================= */

void ground_truth_init(GroundTruth *truth) {
    truth->labels = NULL;
    truth->count = 0;
    truth->capacity = 0;
}

void ground_truth_free(GroundTruth *truth) {
    if (truth == NULL) return;
    free(truth->labels);
    ground_truth_init(truth);
}

static int truth_add(GroundTruth *truth, int label) {
    if (truth->count == truth->capacity) {
        int new_capacity = truth->capacity == 0 ? 64 : truth->capacity * 2;
        int *bigger = (int *)realloc(truth->labels, sizeof(int) * (size_t)new_capacity);
        if (bigger == NULL) return 0;
        truth->labels = bigger;
        truth->capacity = new_capacity;
    }
    truth->labels[truth->count++] = label;
    return 1;
}

/* Adds one event and its label. Returns 1 ok, 0 out of memory. */
static int emit(EventList *events, GroundTruth *truth, long long t, const char *ip,
                const char *user, int success, int label) {
    LoginEvent e;
    memset(&e, 0, sizeof e);
    e.timestamp = t;
    copy_text(e.ip, EVENT_IP_MAX, ip);
    copy_text(e.username, EVENT_USER_MAX, user);
    e.success = success;
    return event_list_add(events, &e) && truth_add(truth, label);
}

/* ---- normal users ----
 * Each user logs in now and then (every 5-40 minutes). A login "session" is
 * usually a success; sometimes 1-2 typos first; rarely 3-4 failures
 * (forgotten password). Gaps between tries: 3-15 seconds. */
static int add_session(EventList *ev, GroundTruth *tr, Rng *rng, long long t,
                       const char *ip, const char *user) {
    int roll = rng_range(rng, 1, 100);
    int typos = roll <= 70 ? 0 : roll <= 90 ? 1 : roll <= 98 ? 2 : rng_range(rng, 3, 4);
    for (int i = 0; i < typos; i++) {
        if (!emit(ev, tr, t, ip, user, 0, LABEL_NORMAL)) return 0;
        t += rng_range(rng, 3, 15);
    }
    return emit(ev, tr, t, ip, user, 1, LABEL_NORMAL);
}

static int add_background(const SimConfig *c, EventList *ev, GroundTruth *tr, Rng *rng, int seconds) {
    char ip[EVENT_IP_MAX], user[EVENT_USER_MAX];
    long long end = c->start_time + seconds;

    for (int u = 0; u < c->normal_users; u++) {
        snprintf(ip, sizeof ip, "10.0.%d.%d", u / 200, 10 + u % 200);
        snprintf(user, sizeof user, "employee%02d", u + 1);
        long long t = c->start_time + rng_range(rng, 0, 600);
        while (t < end) {
            if (!add_session(ev, tr, rng, t, ip, user)) return 0;
            t += rng_range(rng, 300, 2400);
        }
    }
    if (c->include_office_nat) {
        /* 8 people share one public IP (like an office router).
         * Different usernames from one IP - but normal behaviour. */
        for (int u = 0; u < 8; u++) {
            snprintf(user, sizeof user, "staff%02d", u + 1);
            long long t = c->start_time + rng_range(rng, 0, 900);
            while (t < end) {
                if (!add_session(ev, tr, rng, t, "10.10.0.1", user)) return 0;
                t += rng_range(rng, 600, 3000);
            }
        }
    }
    return 1;
}

/* ---- attacks ---- */

static void attacker_ip(int type, int index, char *ip, int size) {
    switch (type) {
    case LABEL_FAST:     snprintf(ip, (size_t)size, "185.220.%d.%d", index / 250, 1 + index % 250); break;
    case LABEL_SLOW:     snprintf(ip, (size_t)size, "45.83.%d.%d", index / 250, 1 + index % 250); break;
    case LABEL_STUFFING: snprintf(ip, (size_t)size, "91.240.%d.%d", index / 250, 1 + index % 250); break;
    default:             snprintf(ip, (size_t)size, "198.51.%d.%d", index / 250, 1 + index % 250); break;
    }
}

/* Returns the time of the last attack event (or start if none), -1 on error. */
static long long add_attack(const SimConfig *c, EventList *ev, GroundTruth *tr, Rng *rng) {
    char ip[EVENT_IP_MAX], user[EVENT_USER_MAX];
    int type = c->attack_type;
    int ips = c->attacker_ips < 1 ? 1 : c->attacker_ips;
    long long last = c->start_time;
    if (type <= LABEL_NORMAL || type >= LABEL_COUNT || c->attempts <= 0) return last;

    /* share the attempts between the IPs as evenly as possible */
    for (int k = 0; k < ips; k++) {
        int share = c->attempts / ips + (k < c->attempts % ips ? 1 : 0);
        attacker_ip(type, k, ip, sizeof ip);
        /* attack starts after a minute of normal traffic; IPs are staggered */
        long long t = c->start_time + 60 + rng_range(rng, 0, type == LABEL_DISTRIBUTED ? 300 : 30);

        for (int a = 0; a < share; a++) {
            int success = 0;
            switch (type) {
            case LABEL_FAST:          /* 1-2 s apart, common names or the target */
                if (c->target_username[0] && rng_range(rng, 1, 2) == 1) strcpy(user, c->target_username);
                else strcpy(user, COMMON_NAMES[rng_range(rng, 0, COMMON_NAME_COUNT - 1)]);
                break;
            case LABEL_SLOW:          /* one target, 60-150 s apart */
                strcpy(user, c->target_username[0] ? c->target_username : "root");
                break;
            case LABEL_STUFFING:      /* a new leaked username every try, 20-40 s apart */
                snprintf(user, sizeof user, "leak%02d_%04d", k, a + 1);
                success = rng_range(rng, 1, 100) <= 3;          /* a few leaked pairs work */
                break;
            default:                  /* distributed: one target, 60-180 s apart per IP */
                strcpy(user, c->target_username[0] ? c->target_username : "admin");
                break;
            }
            if (!emit(ev, tr, t, ip, user, success, type)) return -1;
            if (t > last) last = t;
            if (type == LABEL_FAST)          t += rng_range(rng, 1, 2);
            else if (type == LABEL_SLOW)     t += rng_range(rng, 60, 150);
            else if (type == LABEL_STUFFING) t += rng_range(rng, 20, 40);
            else                             t += rng_range(rng, 60, 180);
        }
    }
    return last;
}

/* ======================= merge sort (by timestamp, stable) ======================= */

/* Merges the sorted halves [left, mid) and [mid, right) using temp arrays. */
static void merge(LoginEvent *e, int *lab, LoginEvent *te, int *tl, int left, int mid, int right) {
    int i = left, j = mid, k = left;
    while (i < mid && j < right) {
        /* "<=" keeps equal timestamps in their original order: stable */
        if (e[i].timestamp <= e[j].timestamp) { te[k] = e[i]; tl[k] = lab[i]; i++; }
        else                                  { te[k] = e[j]; tl[k] = lab[j]; j++; }
        k++;
    }
    while (i < mid)   { te[k] = e[i]; tl[k] = lab[i]; i++; k++; }
    while (j < right) { te[k] = e[j]; tl[k] = lab[j]; j++; k++; }
    for (k = left; k < right; k++) { e[k] = te[k]; lab[k] = tl[k]; }
}

/* Bottom-up merge sort: merge runs of width 1, 2, 4, 8, ... (no recursion). */
static int sort_by_time(EventList *events, GroundTruth *truth) {
    int n = events->count;
    if (n < 2) return 1;
    LoginEvent *temp_events = (LoginEvent *)malloc(sizeof(LoginEvent) * (size_t)n);
    int *temp_labels = (int *)malloc(sizeof(int) * (size_t)n);
    if (temp_events == NULL || temp_labels == NULL) {
        free(temp_events);
        free(temp_labels);
        return 0;
    }
    for (int width = 1; width < n; width *= 2) {
        for (int left = 0; left < n - width; left += 2 * width) {
            int mid = left + width;
            int right = left + 2 * width < n ? left + 2 * width : n;
            merge(events->items, truth->labels, temp_events, temp_labels, left, mid, right);
        }
    }
    free(temp_events);
    free(temp_labels);
    return 1;
}

/* ======================= public functions ======================= */

/* Mixed scenario: every attack type once, each with sensible sizes. */
static long long add_mixed(const SimConfig *config, EventList *ev, GroundTruth *tr, Rng *rng) {
    long long last = config->start_time;
    for (int type = LABEL_FAST; type < LABEL_COUNT; type++) {
        SimConfig part = *config;
        part.attack_type = type;
        part.attacker_ips = 1;
        if (type == LABEL_SLOW) {
            part.attempts = config->attempts < 25 ? config->attempts : 25;
            strcpy(part.target_username, "root");
        } else if (type == LABEL_DISTRIBUTED) {
            part.attacker_ips = config->attacker_ips < 8 ? 8 : config->attacker_ips;
            part.attempts = part.attacker_ips * 4;
        }
        long long end = add_attack(&part, ev, tr, rng);
        if (end < 0) return -1;
        if (end > last) last = end;
    }
    return last;
}

int sim_generate(const SimConfig *config, EventList *events, GroundTruth *truth) {
    Rng rng;
    event_list_free(events);
    ground_truth_free(truth);
    rng_seed(&rng, config->seed);

    /* attack first so we know how long the background must last */
    long long attack_end = config->attack_type == SIM_MIXED
                         ? add_mixed(config, events, truth, &rng)
                         : add_attack(config, events, truth, &rng);
    if (attack_end < 0) return -1;
    int seconds = config->background_seconds;
    if (attack_end - config->start_time + 120 > seconds)
        seconds = (int)(attack_end - config->start_time + 120);

    if (!add_background(config, events, truth, &rng, seconds)) return -1;
    if (!sort_by_time(events, truth)) return -1;
    return events->count;
}

int sim_write_csv(const EventList *events, const char *path, const char *header_comment) {
    char line[160];
    FILE *file = fopen(path, "w");
    if (file == NULL) return 0;
    if (header_comment != NULL) fprintf(file, "# %s\n", header_comment);
    for (int i = 0; i < events->count; i++) {
        event_to_csv(&events->items[i], line, sizeof line);
        fprintf(file, "%s\n", line);
    }
    return fclose(file) == 0;
}
