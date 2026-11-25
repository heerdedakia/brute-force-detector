/*
 * baseline.c - single fixed rule (see baseline.h).
 * A ban simply ends when the IP's next event arrives after ban_until, so the
 * baseline needs no queue. That keeps it as simple as a real "fail2ban
 * style" one-rule system.
 */
#include <stdlib.h>
#include <string.h>
#include "baseline.h"

static void free_record(void *value) {
    BaselineRecord *rec = (BaselineRecord *)value;
    if (rec == NULL) return;
    deque_destroy(rec->window);
    free(rec);
}

BaselineDetector *baseline_create(int ban_duration) {
    BaselineDetector *b = (BaselineDetector *)calloc(1, sizeof(BaselineDetector));
    if (b == NULL) return NULL;
    b->ips = ht_create(64);
    if (b->ips == NULL) {
        free(b);
        return NULL;
    }
    b->ban_duration = ban_duration > 0 ? ban_duration : 300;
    return b;
}

void baseline_destroy(BaselineDetector *b) {
    if (b == NULL) return;
    ht_destroy(b->ips, free_record);
    free(b);
}

int baseline_process(BaselineDetector *b, const LoginEvent *event) {
    if (b == NULL || event == NULL) return 0;
    BaselineRecord *rec = (BaselineRecord *)ht_get(b->ips, event->ip);
    if (rec == NULL) {
        rec = (BaselineRecord *)calloc(1, sizeof(BaselineRecord));
        if (rec == NULL) return 0;
        rec->window = deque_create(8);
        if (rec->window == NULL || !ht_put(b->ips, event->ip, rec)) {
            free_record(rec);
            return 0;
        }
        rec->first_seen = event->timestamp;
    }

    if (rec->is_banned && event->timestamp >= rec->ban_until) rec->is_banned = 0;
    if (rec->is_banned) {
        b->blocked_events++;
        return 1;
    }
    if (event->success) return 0;

    deque_push_rear(rec->window, event->timestamp);
    deque_remove_older_than(rec->window, event->timestamp - BASELINE_WINDOW + 1);
    if (deque_size(rec->window) >= BASELINE_LIMIT) {
        rec->is_banned = 1;
        rec->ban_until = event->timestamp + b->ban_duration;
        rec->times_banned++;
        if (rec->first_ban_at == 0) rec->first_ban_at = event->timestamp;
        b->total_bans++;
        while (deque_pop_front(rec->window, NULL)) { }    /* start fresh after a ban */
    }
    return 0;
}

const BaselineRecord *baseline_get(const BaselineDetector *b, const char *ip) {
    return b == NULL ? NULL : (const BaselineRecord *)ht_get(b->ips, ip);
}
