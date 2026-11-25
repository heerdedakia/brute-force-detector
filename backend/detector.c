/*
 * detector.c - multi-window detection engine (see detector.h and
 * docs/DETECTION.md for the formula and every threshold).
 *
 * THREAT SCORE (recomputed after every event and on every tick):
 *
 *   score = weight_short    * failures in last 10 s
 *         + weight_medium   * failures in last 10 min
 *         + weight_long     * failures in last 1 h
 *         + weight_username * (distinct usernames failed - 1)
 *         + weight_target   * failures on a username under distributed attack
 *         + weight_recent   * (1 if the last failure was within 10 s, else 0)
 *
 * DECAY: old timestamps fall out of the front of each deque as time passes,
 * so the window counts (and therefore the score) shrink by themselves when an
 * IP goes quiet: after 10 s the short part is gone, after 10 min the medium
 * part, after 1 h everything. When the 1 h window is empty the IP's activity
 * period ends and its categories/username list are cleared.
 *
 * BAN: after a FAILED login, if score >= score_threshold and the IP is not
 * already banned, a simulated ban is put in the circular queue.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detector.h"

/* ======================= settings ======================= */

void settings_set_defaults(Settings *s) {
    s->short_threshold = 5;
    s->medium_threshold = 8;
    s->long_threshold = 15;
    s->score_threshold = 60.0;
    s->ban_duration = 300;
    s->weight_short = 8.0;
    s->weight_medium = 3.0;
    s->weight_long = 1.5;
    s->weight_username = 8.0;
    s->weight_target = 10.0;
    s->weight_recent = 5.0;
}

static int clamp_int(int *value, int low, int high) {
    if (*value < low)  { *value = low;  return 0; }
    if (*value > high) { *value = high; return 0; }
    return 1;
}

static int clamp_double(double *value, double low, double high) {
    if (!(*value >= low)) { *value = low;  return 0; }   /* also catches NaN */
    if (*value > high)    { *value = high; return 0; }
    return 1;
}

int settings_validate(Settings *s) {
    int ok = 1;
    ok &= clamp_int(&s->short_threshold, 1, 1000);
    ok &= clamp_int(&s->medium_threshold, 1, 10000);
    ok &= clamp_int(&s->long_threshold, 1, 100000);
    ok &= clamp_double(&s->score_threshold, 1.0, 100000.0);
    ok &= clamp_int(&s->ban_duration, 10, 86400);
    ok &= clamp_double(&s->weight_short, 0.0, 1000.0);
    ok &= clamp_double(&s->weight_medium, 0.0, 1000.0);
    ok &= clamp_double(&s->weight_long, 0.0, 1000.0);
    ok &= clamp_double(&s->weight_username, 0.0, 1000.0);
    ok &= clamp_double(&s->weight_target, 0.0, 1000.0);
    ok &= clamp_double(&s->weight_recent, 0.0, 1000.0);
    return ok;
}

/* ======================= display helpers ======================= */

static const char *CATEGORY_NAMES[CATEGORY_COUNT] = {
    "Fast brute-force", "Low-and-slow", "Credential stuffing", "Distributed attack"
};

const char *category_name_of_bit(int bit_index) {
    if (bit_index < 0 || bit_index >= CATEGORY_COUNT) return "Unknown";
    return CATEGORY_NAMES[bit_index];
}

/* When an IP has several categories we show the most specific one. */
const char *category_primary_name(int flags) {
    if (flags & CAT_FAST)        return CATEGORY_NAMES[0];
    if (flags & CAT_STUFFING)    return CATEGORY_NAMES[2];
    if (flags & CAT_DISTRIBUTED) return CATEGORY_NAMES[3];
    if (flags & CAT_SLOW)        return CATEGORY_NAMES[1];
    return "None";
}

const char *severity_for_score(double score, double threshold) {
    if (score >= threshold)        return "critical";
    if (score >= threshold * 0.7)  return "high";
    if (score >= threshold * 0.4)  return "medium";
    return "low";
}

/* ======================= records: create / free ======================= */

static void free_ip_record(void *value) {
    IpRecord *rec = (IpRecord *)value;
    if (rec == NULL) return;
    deque_destroy(rec->short_window);
    deque_destroy(rec->medium_window);
    deque_destroy(rec->long_window);
    ht_destroy(rec->failed_usernames, free);   /* values are malloc'd int* */
    free(rec);
}

static void free_user_stats(void *value) {
    UserStats *user = (UserStats *)value;
    if (user == NULL) return;
    ht_destroy(user->failing_ips, free);       /* values are malloc'd long long* */
    free(user);
}

static IpRecord *new_ip_record(const char *ip, long long now) {
    IpRecord *rec = (IpRecord *)calloc(1, sizeof(IpRecord));   /* all counters 0 */
    if (rec == NULL) return NULL;
    copy_text(rec->ip, EVENT_IP_MAX, ip);
    rec->short_window = deque_create(4);
    rec->medium_window = deque_create(8);
    rec->long_window = deque_create(8);
    rec->failed_usernames = ht_create(4);
    if (!rec->short_window || !rec->medium_window || !rec->long_window || !rec->failed_usernames) {
        free_ip_record(rec);
        return NULL;
    }
    rec->first_seen = now;
    return rec;
}

static UserStats *new_user_stats(const char *username) {
    UserStats *user = (UserStats *)calloc(1, sizeof(UserStats));
    if (user == NULL) return NULL;
    copy_text(user->username, EVENT_USER_MAX, username);
    user->failing_ips = ht_create(4);
    if (user->failing_ips == NULL) {
        free(user);
        return NULL;
    }
    return user;
}

/* ======================= create / destroy / reset ======================= */

/* Creates the containers. Returns 1 ok, 0 out of memory. */
static int create_containers(Detector *d) {
    d->ips = ht_create(64);
    d->users = ht_create(64);
    d->ranking = heap_create(64);
    d->bans = cq_create(BAN_QUEUE_CAPACITY);
    d->alerts = alert_list_create(ALERT_HISTORY_MAX);
    return d->ips && d->users && d->ranking && d->bans && d->alerts;
}

static void destroy_containers(Detector *d) {
    ht_destroy(d->ips, free_ip_record);
    ht_destroy(d->users, free_user_stats);
    heap_destroy(d->ranking);
    cq_destroy(d->bans);
    alert_list_destroy(d->alerts);
    d->ips = NULL; d->users = NULL; d->ranking = NULL; d->bans = NULL; d->alerts = NULL;
}

static void zero_counters(Detector *d) {
    d->now = 0;
    d->last_tick = 0;
    d->last_user_prune = 0;
    d->total_events = d->total_failed = d->total_success = 0;
    d->blocked_events = d->out_of_order_events = 0;
    d->total_bans = d->bans_dropped = d->distributed_usernames = 0;
    for (int i = 0; i < CATEGORY_COUNT; i++) d->category_counts[i] = 0;
}

Detector *detector_create(const Settings *settings) {
    Detector *d = (Detector *)calloc(1, sizeof(Detector));
    if (d == NULL) return NULL;
    if (settings != NULL) d->settings = *settings;
    else settings_set_defaults(&d->settings);
    settings_validate(&d->settings);
    zero_counters(d);
    if (!create_containers(d)) {
        destroy_containers(d);
        free(d);
        return NULL;
    }
    return d;
}

void detector_destroy(Detector *d) {
    if (d == NULL) return;
    destroy_containers(d);
    free(d);
}

int detector_reset(Detector *d) {
    if (d == NULL) return 0;
    destroy_containers(d);
    zero_counters(d);
    return create_containers(d);
}

void detector_apply_settings(Detector *d, const Settings *settings) {
    if (d == NULL || settings == NULL) return;
    d->settings = *settings;
    settings_validate(&d->settings);
}

/* ======================= alerts ======================= */

static void add_alert(Detector *d, const char *ip, const char *username, const char *category,
                      double score, const char *message) {
    AlertNode alert;
    memset(&alert, 0, sizeof alert);
    alert.time = d->now;
    copy_text(alert.ip, ALERT_IP_MAX, ip ? ip : "");
    copy_text(alert.username, ALERT_USER_MAX, username ? username : "");
    copy_text(alert.category, ALERT_CATEGORY_MAX, category);
    copy_text(alert.severity, (int)sizeof alert.severity, severity_for_score(score, d->settings.score_threshold));
    alert.score = score;
    copy_text(alert.message, ALERT_MESSAGE_MAX, message);
    alert_list_add(d->alerts, &alert);
}

/* ======================= scoring ======================= */

/* Remove timestamps that have left each window, measured from 'now'. */
static void slide_windows(IpRecord *rec, long long now) {
    deque_remove_older_than(rec->short_window,  now - SHORT_WINDOW + 1);
    deque_remove_older_than(rec->medium_window, now - MEDIUM_WINDOW + 1);
    deque_remove_older_than(rec->long_window,   now - LONG_WINDOW + 1);
}

static double compute_score(const Settings *s, const IpRecord *rec, long long now) {
    int distinct_usernames = ht_count(rec->failed_usernames);
    int extra_usernames = distinct_usernames > 1 ? distinct_usernames - 1 : 0;
    int recent = rec->last_failure > 0 && now - rec->last_failure < SHORT_WINDOW;

    return s->weight_short    * deque_size(rec->short_window)
         + s->weight_medium   * deque_size(rec->medium_window)
         + s->weight_long     * deque_size(rec->long_window)
         + s->weight_username * extra_usernames
         + s->weight_target   * rec->target_failures
         + s->weight_recent   * (recent ? 1 : 0);
}

/* Put the new score in the record AND in the heap (O(log n)). */
static void store_score(Detector *d, IpRecord *rec, double score) {
    rec->score = score;
    if (score > 0.0) heap_set(d->ranking, rec->ip, score);
    else heap_remove(d->ranking, rec->ip);       /* quiet IPs leave the ranking */
}

/* The IP has been quiet for a full hour: start a fresh activity period. */
static void end_activity_period(IpRecord *rec) {
    HashTable *fresh = ht_create(4);
    if (fresh != NULL) {
        ht_destroy(rec->failed_usernames, free);
        rec->failed_usernames = fresh;
    }
    rec->target_failures = 0;
    rec->flags = 0;
}

/* ======================= categories ======================= */

static void flag_category(Detector *d, IpRecord *rec, int flag, const char *username) {
    char message[ALERT_MESSAGE_MAX];
    if (rec->flags & flag) return;                /* already flagged: no repeat alert */
    rec->flags |= flag;
    if (rec->first_alert_at == 0) rec->first_alert_at = d->now;

    int bit = 0;
    while ((1 << bit) != flag) bit++;
    if (!(rec->ever_flags & flag)) {
        rec->ever_flags |= flag;
        d->category_counts[bit]++;
    }

    switch (flag) {
    case CAT_FAST:
        snprintf(message, sizeof message, "Suspicious fast brute-force activity: %d failures in 10 s",
                 deque_size(rec->short_window));
        break;
    case CAT_SLOW:
        snprintf(message, sizeof message, "Possible low-and-slow attack: %d failures in 10 min, %d in 1 h",
                 deque_size(rec->medium_window), deque_size(rec->long_window));
        break;
    case CAT_STUFFING:
        snprintf(message, sizeof message, "Possible credential stuffing: %d different usernames failed",
                 ht_count(rec->failed_usernames));
        break;
    default:
        snprintf(message, sizeof message, "IP takes part in a possible distributed attack on '%s'",
                 username);
        break;
    }
    add_alert(d, rec->ip, username, CATEGORY_NAMES[bit], rec->score, message);
}

static void check_categories(Detector *d, IpRecord *rec, const char *username) {
    const Settings *s = &d->settings;
    int short_count = deque_size(rec->short_window);
    int medium_count = deque_size(rec->medium_window);
    int long_count = deque_size(rec->long_window);

    if (short_count >= s->short_threshold)
        flag_category(d, rec, CAT_FAST, username);
    /* "spread out": the windows are full even though the short window is not */
    if ((medium_count >= s->medium_threshold || long_count >= s->long_threshold) &&
        short_count < s->short_threshold)
        flag_category(d, rec, CAT_SLOW, username);
    if (ht_count(rec->failed_usernames) >= STUFFING_USERNAME_LIMIT && long_count >= STUFFING_MIN_FAILURES)
        flag_category(d, rec, CAT_STUFFING, username);
    if (rec->target_failures >= DISTRIBUTED_MIN_FAILURES)
        flag_category(d, rec, CAT_DISTRIBUTED, username);
}

/* Username side of the distributed-attack rule. Returns how many times THIS
 * IP failed on the username if the username is under attack, else 0. */
static int update_user_stats(Detector *d, const char *username, const char *ip,
                             long long when, int failures_from_ip) {
    UserStats *user = (UserStats *)ht_get(d->users, username);
    if (user == NULL) {
        user = new_user_stats(username);
        if (user == NULL || !ht_put(d->users, username, user)) {
            free_user_stats(user);
            return 0;
        }
    }
    user->total_failures++;

    long long *last = (long long *)ht_get(user->failing_ips, ip);
    if (last == NULL) {
        last = (long long *)malloc(sizeof(long long));
        if (last != NULL && !ht_put(user->failing_ips, ip, last)) {
            free(last);
            last = NULL;
        }
    }
    if (last != NULL) *last = when;

    int distinct_ips = ht_count(user->failing_ips);
    if (!user->under_attack && distinct_ips >= DISTRIBUTED_IP_LIMIT) {
        char message[ALERT_MESSAGE_MAX];
        user->under_attack = 1;
        user->times_flagged++;
        if (user->times_flagged == 1) d->distributed_usernames++;
        snprintf(message, sizeof message,
                 "Possible distributed attack: %d different IPs failing on username '%s' within 1 h",
                 distinct_ips, username);
        add_alert(d, "", username, "Distributed attack", d->settings.score_threshold * 0.7, message);
    }
    return user->under_attack ? failures_from_ip : 0;
}

/* The score crossed the ban threshold before any category rule fired
 * (for example a fast bot that also rotates usernames gets banned after 4
 * tries, before the 10 s window reaches 5). Then the category is the part of
 * the score formula that contributed the MOST points. */
static void flag_dominant_category(Detector *d, IpRecord *rec) {
    const Settings *s = &d->settings;
    int distinct = ht_count(rec->failed_usernames);
    int recent = rec->last_failure > 0 && d->now - rec->last_failure < SHORT_WINDOW;
    double fast_part = s->weight_short * deque_size(rec->short_window) + s->weight_recent * recent;
    double slow_part = s->weight_medium * deque_size(rec->medium_window)
                     + s->weight_long * deque_size(rec->long_window);
    double stuffing_part = s->weight_username * (distinct > 1 ? distinct - 1 : 0);
    double distributed_part = s->weight_target * rec->target_failures;

    int best = CAT_FAST;
    double best_points = fast_part;
    if (slow_part > best_points)        { best = CAT_SLOW;        best_points = slow_part; }
    if (stuffing_part > best_points)    { best = CAT_STUFFING;    best_points = stuffing_part; }
    if (distributed_part > best_points) { best = CAT_DISTRIBUTED; best_points = distributed_part; }
    flag_category(d, rec, best, "");
}

/* ======================= bans ======================= */

static void start_ban(Detector *d, IpRecord *rec) {
    BanEntry entry;
    BanEntry last;
    char message[ALERT_MESSAGE_MAX];

    memset(&entry, 0, sizeof entry);
    copy_text(entry.ip, CQ_IP_MAX, rec->ip);
    if (rec->flags == 0) flag_dominant_category(d, rec);
    copy_text(entry.reason, CQ_REASON_MAX, rec->flags ? category_primary_name(rec->flags) : "High threat score");
    entry.score = rec->score;
    entry.blocked_at = d->now;
    entry.expires_at = d->now + d->settings.ban_duration;
    entry.active = 1;

    /* If the ban duration was made SHORTER, a new ban could end before an
     * older one. To keep the queue sorted by expiry (needed for FIFO expiry)
     * the new ban is extended to end together with the newest older ban.
     * It is never shortened, and nothing ever expires out of order. */
    if (cq_peek_rear(d->bans, &last) && entry.expires_at < last.expires_at)
        entry.expires_at = last.expires_at;

    if (cq_enqueue(d->bans, &entry) != CQ_OK) {
        d->bans_dropped++;                      /* queue full: cannot track expiry */
        return;
    }
    rec->is_banned = 1;
    rec->ban_expires_at = entry.expires_at;
    if (rec->first_alert_at == 0) rec->first_alert_at = d->now;
    rec->times_banned++;
    d->total_bans++;
    snprintf(message, sizeof message, "Simulated block for %lld s (score %.1f, %s)",
             entry.expires_at - entry.blocked_at, rec->score, entry.reason);
    add_alert(d, rec->ip, "", "Blocked", rec->score, message);
}

/* Pop every ban that has ended (event/simulation clock, not wall clock).
 * cq_expire hands them back in batches of 16 until none are left. */
static void expire_bans(Detector *d) {
    BanEntry ended[16];
    int count;
    do {
        count = cq_expire(d->bans, d->now, ended, 16);
        for (int i = 0; i < count; i++) {
            IpRecord *rec = (IpRecord *)ht_get(d->ips, ended[i].ip);
            if (rec != NULL && rec->is_banned) {
                rec->is_banned = 0;
                add_alert(d, rec->ip, "", "Unblocked", 0.0, "Simulated block expired");
            }
        }
    } while (count == 16);
}

int detector_unblock(Detector *d, const char *ip) {
    if (d == NULL || ip == NULL) return 0;
    IpRecord *rec = (IpRecord *)ht_get(d->ips, ip);
    if (rec == NULL || !rec->is_banned) return 0;

    cq_deactivate(d->bans, ip);                 /* lazy deletion inside the queue */
    rec->is_banned = 0;
    /* fresh start: an administrator decided this IP is OK for now */
    while (deque_pop_front(rec->short_window, NULL)) { }
    while (deque_pop_front(rec->medium_window, NULL)) { }
    while (deque_pop_front(rec->long_window, NULL)) { }
    end_activity_period(rec);
    rec->last_failure = 0;
    store_score(d, rec, 0.0);
    add_alert(d, ip, "", "Unblocked", 0.0, "Manually unblocked (simulation) - history cleared");
    return 1;
}

/* ======================= main entry points ======================= */

static IpRecord *get_or_create_ip(Detector *d, const char *ip) {
    IpRecord *rec = (IpRecord *)ht_get(d->ips, ip);
    if (rec != NULL) return rec;
    rec = new_ip_record(ip, d->now);
    if (rec == NULL) return NULL;
    if (!ht_put(d->ips, ip, rec)) {
        free_ip_record(rec);
        return NULL;
    }
    return rec;
}

/* A SUCCESSFUL login proves this IP knows the password of this username, so
 * earlier typos for that username from this IP no longer count towards
 * "many different usernames" (credential stuffing) or towards the username's
 * list of failing IPs (distributed attack). The time windows are NOT changed. */
static void forgive_username(Detector *d, IpRecord *rec, const char *username) {
    void *value = NULL;
    if (ht_remove(rec->failed_usernames, username, &value)) free(value);
    UserStats *user = (UserStats *)ht_get(d->users, username);
    if (user != NULL && ht_remove(user->failing_ips, rec->ip, &value)) free(value);
}

static void set_label(EventResult *r, const char *text) {
    copy_text(r->label, (int)sizeof r->label, text);
}

void detector_process(Detector *d, const LoginEvent *event, EventResult *result) {
    EventResult local;
    if (result == NULL) result = &local;
    memset(result, 0, sizeof *result);
    if (d == NULL || event == NULL) return;

    /* 1. advance the simulation clock */
    long long when = event->timestamp;
    if (when < d->now) {                        /* out of order: treat as "now" */
        when = d->now;
        d->out_of_order_events++;
    }
    d->now = when;
    if (d->last_tick == 0) d->last_tick = when;
    if (d->last_user_prune == 0) d->last_user_prune = when;
    d->total_events++;
    if (event->success) d->total_success++;
    else d->total_failed++;

    /* 2. bans that ended before this event are lifted first */
    expire_bans(d);

    IpRecord *rec = get_or_create_ip(d, event->ip);
    if (rec == NULL) { set_label(result, "Error"); return; }
    rec->last_activity = when;

    /* 3. a banned IP is stopped (simulated) and does not touch the windows */
    if (rec->is_banned) {
        rec->blocked_attempts++;
        d->blocked_events++;
        result->blocked = 1;
        result->flags = rec->flags;
        result->score = rec->score;
        set_label(result, "Blocked");
        return;
    }
    rec->total_attempts++;

    /* 4. a failure goes into all three windows and the username tables */
    if (!event->success) {
        rec->total_failures++;
        rec->last_failure = when;
        deque_push_rear(rec->short_window, when);
        deque_push_rear(rec->medium_window, when);
        deque_push_rear(rec->long_window, when);

        int *count = (int *)ht_get(rec->failed_usernames, event->username);
        if (count == NULL) {
            count = (int *)malloc(sizeof(int));
            if (count != NULL) {
                *count = 0;
                if (!ht_put(rec->failed_usernames, event->username, count)) { free(count); count = NULL; }
            }
        }
        int failures_here = 0;
        if (count != NULL) failures_here = ++(*count);

        int targeted = update_user_stats(d, event->username, rec->ip, when, failures_here);
        if (targeted > rec->target_failures) rec->target_failures = targeted;
    } else {
        rec->total_successes++;
        forgive_username(d, rec, event->username);
    }

    /* 5. slide the windows, rescore, re-rank */
    slide_windows(rec, when);
    store_score(d, rec, compute_score(&d->settings, rec, when));

    /* 6. categories, then a possible ban (bans only follow a FAILED login) */
    if (!event->success) {
        check_categories(d, rec, event->username);
        if (rec->score >= d->settings.score_threshold) {
            start_ban(d, rec);
            result->newly_banned = rec->is_banned;
        }
    }

    result->flags = rec->flags;
    result->score = rec->score;
    if (result->newly_banned)      set_label(result, "Blocked now");
    else if (rec->flags)           set_label(result, category_primary_name(rec->flags));
    else if (event->success)       set_label(result, "Normal");
    else                           set_label(result, "Failed login");

    /* 7. let quiet IPs decay from time to time */
    detector_tick(d, when);
}

/* ---- tick helpers ---- */

typedef struct {
    char (*keys)[HT_KEY_MAX];
    int count;
    int capacity;
} KeyList;

static void key_list_add(KeyList *list, const char *key) {
    if (list->count == list->capacity) {
        int new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        char (*bigger)[HT_KEY_MAX] = realloc(list->keys, sizeof(*bigger) * (size_t)new_capacity);
        if (bigger == NULL) return;              /* skip: will be retried next tick */
        list->keys = bigger;
        list->capacity = new_capacity;
    }
    strcpy(list->keys[list->count++], key);
}

/* Forget IPs that last failed on this username more than 1 h ago.
 * We cannot remove inside ht_for_each, so we first collect the keys. */
static void prune_user(UserStats *user, long long now) {
    KeyList old = {NULL, 0, 0};
    for (int b = 0; b < user->failing_ips->bucket_count; b++)
        for (HashNode *n = user->failing_ips->buckets[b]; n != NULL; n = n->next)
            if (*(long long *)n->value <= now - LONG_WINDOW) key_list_add(&old, n->key);

    for (int i = 0; i < old.count; i++) {
        void *value = NULL;
        if (ht_remove(user->failing_ips, old.keys[i], &value)) free(value);
    }
    free(old.keys);
    if (user->under_attack && ht_count(user->failing_ips) < DISTRIBUTED_IP_LIMIT)
        user->under_attack = 0;
}

void detector_tick(Detector *d, long long now) {
    if (d == NULL) return;
    if (now > d->now) d->now = now;
    expire_bans(d);
    if (d->now - d->last_tick < TICK_INTERVAL) return;
    d->last_tick = d->now;

    /* Only IPs IN THE HEAP (score > 0) can still decay, so we revisit just
     * those instead of every IP ever seen. We copy their keys first because
     * store_score() moves items around inside the heap. */
    int active = d->ranking->size;
    if (active > 0) {
        char (*keys)[HEAP_KEY_MAX] = malloc(sizeof(*keys) * (size_t)active);
        if (keys != NULL) {
            for (int i = 0; i < active; i++) strcpy(keys[i], d->ranking->items[i].key);
            for (int i = 0; i < active; i++) {
                IpRecord *rec = (IpRecord *)ht_get(d->ips, keys[i]);
                if (rec == NULL) continue;
                slide_windows(rec, d->now);
                if (deque_is_empty(rec->long_window) && !rec->is_banned) end_activity_period(rec);
                store_score(d, rec, compute_score(&d->settings, rec, d->now));
            }
            free(keys);
        }
    }

    /* Username tables change slowly (1 h window): prune them once a minute. */
    if (d->now - d->last_user_prune >= USER_PRUNE_INTERVAL) {
        d->last_user_prune = d->now;
        for (int b = 0; b < d->users->bucket_count; b++)
            for (HashNode *n = d->users->buckets[b]; n != NULL; n = n->next)
                prune_user((UserStats *)n->value, d->now);
    }
}

/* ======================= queries ======================= */

const IpRecord *detector_get_ip(const Detector *d, const char *ip) {
    return d == NULL ? NULL : (const IpRecord *)ht_get(d->ips, ip);
}

const UserStats *detector_get_user(const Detector *d, const char *username) {
    return d == NULL ? NULL : (const UserStats *)ht_get(d->users, username);
}

int detector_top(const Detector *d, int k, HeapItem *out) {
    return d == NULL ? 0 : heap_top_k(d->ranking, k, out);
}

int detector_active_threats(const Detector *d) {
    int count = 0;
    if (d == NULL) return 0;
    for (int i = 0; i < d->ranking->size; i++)
        if (d->ranking->items[i].priority >= d->settings.score_threshold * 0.4) count++;
    return count;
}
