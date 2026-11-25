/*
 * detector.h - the multi-window detection engine.
 *
 * For every IP we keep THREE sliding windows of failed-login timestamps
 * (deques): 10 seconds, 10 minutes and 1 hour. Every event updates the
 * windows, the threat score, the IP's place in the max heap, and may start
 * a simulated ban (circular queue) or an alert (linked list).
 *
 * Data structures used here:
 *   HashTable  ips       : IP text      -> IpRecord*
 *   HashTable  users     : username     -> UserStats*
 *   Deque x3 per IP      : failure timestamps in each window
 *   HashTable per IP     : username -> int* failures from this IP
 *   HashTable per user   : IP -> long long* last failure time on this user
 *   MaxHeap    ranking   : IP -> threat score (top-K dangerous IPs)
 *   CircularQueue bans   : active simulated bans in expiry order
 *   AlertList  alerts    : newest-first alert history
 *
 * IMPORTANT: blocking is SIMULATED. Nothing on the computer is changed.
 * Wording is cautious: "suspicious", "possible" - never "definitely".
 */
#ifndef DETECTOR_H
#define DETECTOR_H

#include "settings.h"
#include "deque.h"
#include "hashtable.h"
#include "heap.h"
#include "circular_queue.h"
#include "linkedlist.h"
#include "parser.h"

/* ---- window lengths (seconds) ---- */
#define SHORT_WINDOW   10
#define MEDIUM_WINDOW  600
#define LONG_WINDOW    3600

/* ---- fixed rule constants (documented in docs/DETECTION.md) ---- */
#define STUFFING_USERNAME_LIMIT  5   /* distinct usernames failed from one IP       */
#define STUFFING_MIN_FAILURES    5   /* ...together with this many failures in 1 h  */
#define DISTRIBUTED_IP_LIMIT     5   /* distinct IPs failing on one username in 1 h */
#define DISTRIBUTED_MIN_FAILURES 2   /* an IP must fail this often on that username */
#define TICK_INTERVAL            5   /* seconds of simulation time between decays   */
#define USER_PRUNE_INTERVAL      60  /* seconds between clean-ups of username tables */
#define BAN_QUEUE_CAPACITY       4096
#define ALERT_HISTORY_MAX        200

/* ---- category flags (bits, so one IP can have several) ---- */
#define CAT_FAST        1
#define CAT_SLOW        2
#define CAT_STUFFING    4
#define CAT_DISTRIBUTED 8
#define CATEGORY_COUNT  4

typedef struct {
    char ip[EVENT_IP_MAX];
    Deque *short_window;        /* failure timestamps, last 10 s   */
    Deque *medium_window;       /* failure timestamps, last 10 min */
    Deque *long_window;         /* failure timestamps, last 1 h    */
    HashTable *failed_usernames;/* username -> int* failure count  */
    int target_failures;        /* failures on a username under distributed attack */
    double score;               /* current threat score            */
    int flags;                  /* categories seen in the current activity period */
    int ever_flags;             /* every category ever seen (for statistics)      */
    long long first_seen;
    long long last_activity;
    long long last_failure;     /* 0 = never failed                */
    int total_attempts;         /* attempts that reached the detector (not blocked) */
    int total_failures;
    int total_successes;
    int blocked_attempts;       /* attempts made while banned      */
    int is_banned;
    long long ban_expires_at;
    int times_banned;
    long long first_alert_at;   /* time of the first category flag or ban (0 = none) */
} IpRecord;

typedef struct {
    char username[EVENT_USER_MAX];
    HashTable *failing_ips;     /* ip -> long long* time of last failure */
    int total_failures;
    int under_attack;           /* 1 while >= DISTRIBUTED_IP_LIMIT IPs fail on it */
    int times_flagged;
} UserStats;

/* What the detector says about ONE event (for the live event table). */
typedef struct {
    int blocked;                /* 1 = the IP was already banned          */
    int newly_banned;           /* 1 = this event caused a new ban         */
    int flags;                  /* the IP's categories after the event     */
    double score;               /* the IP's score after the event          */
    char label[32];             /* "Normal", "Failed login", "Blocked", ... */
} EventResult;

typedef struct {
    Settings settings;
    HashTable *ips;
    HashTable *users;
    MaxHeap *ranking;
    CircularQueue *bans;
    AlertList *alerts;

    long long now;              /* simulation clock: newest time seen     */
    long long last_tick;
    long long last_user_prune;

    /* counters for the dashboard */
    long long total_events;
    long long total_failed;
    long long total_success;
    long long blocked_events;
    long long out_of_order_events;
    int total_bans;
    int bans_dropped;           /* only if the ban queue was full          */
    int category_counts[CATEGORY_COUNT];   /* IPs that ever had each category */
    int distributed_usernames;  /* usernames ever flagged                  */
} Detector;

Detector *detector_create(const Settings *settings);
void detector_destroy(Detector *d);
int  detector_reset(Detector *d);      /* clears all data, keeps the settings */

/* Feed one event. Events should arrive in time order; an older event is
 * treated as happening "now" (and counted in out_of_order_events). */
void detector_process(Detector *d, const LoginEvent *event, EventResult *result);

/* Advance the simulation clock without an event: expires bans and lets the
 * scores of quiet IPs decay. Call it regularly (cheap if nothing changed). */
void detector_tick(Detector *d, long long now);

/* Manual unblock (simulation only). Also clears the IP's windows so it gets
 * a fresh start. Returns 1 if the IP was banned, 0 otherwise. */
int detector_unblock(Detector *d, const char *ip);

/* New settings. Thresholds apply from the next event; a new ban duration
 * applies to NEW bans only (running bans keep their expiry time). */
void detector_apply_settings(Detector *d, const Settings *settings);

const IpRecord  *detector_get_ip(const Detector *d, const char *ip);
const UserStats *detector_get_user(const Detector *d, const char *username);
int detector_top(const Detector *d, int k, HeapItem *out);     /* top-K by score */
int detector_active_threats(const Detector *d);  /* IPs with score >= 40% of threshold */

/* Helpers for display */
const char *category_primary_name(int flags);     /* "Fast brute-force", ... or "None" */
const char *category_name_of_bit(int bit_index);  /* 0..3                               */
const char *severity_for_score(double score, double threshold);

#endif
