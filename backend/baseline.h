/*
 * baseline.h - the TRADITIONAL single-rule detector we compare against:
 *     "block an IP after 5 failed logins within 60 seconds".
 * One sliding window per IP (a deque), nothing else: no medium/long windows,
 * no username tracking, no score.
 */
#ifndef BASELINE_H
#define BASELINE_H

#include "hashtable.h"
#include "deque.h"
#include "parser.h"

#define BASELINE_WINDOW 60
#define BASELINE_LIMIT  5

typedef struct {
    Deque *window;           /* failure timestamps in the last 60 s */
    int is_banned;
    long long ban_until;
    int times_banned;
    long long first_ban_at;  /* 0 = never banned */
    long long first_seen;
} BaselineRecord;

typedef struct {
    HashTable *ips;          /* IP -> BaselineRecord* */
    int ban_duration;
    long long total_bans;
    long long blocked_events;
} BaselineDetector;

BaselineDetector *baseline_create(int ban_duration);
void baseline_destroy(BaselineDetector *b);

/* Returns 1 if the event was blocked (IP already banned), else 0. */
int baseline_process(BaselineDetector *b, const LoginEvent *event);

const BaselineRecord *baseline_get(const BaselineDetector *b, const char *ip);

#endif
