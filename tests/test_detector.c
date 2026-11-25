/* Unit tests for the detection engine. Run: make test_detector */
#include <stdio.h>
#include <string.h>
#include "../backend/detector.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

#define T0 1795177815LL     /* 2026-11-20 12:30:15 */

static LoginEvent ev(long long t, const char *ip, const char *user, int success) {
    LoginEvent e;
    memset(&e, 0, sizeof e);
    e.timestamp = t;
    strcpy(e.ip, ip);
    strcpy(e.username, user);
    e.success = success;
    return e;
}

static int has_alert(const Detector *d, const char *category, const char *ip) {
    for (const AlertNode *a = d->alerts->head; a != NULL; a = a->next)
        if (strcmp(a->category, category) == 0 && (ip == NULL || strcmp(a->ip, ip) == 0)) return 1;
    return 0;
}

static void test_fast(void) {
    printf("fast brute-force: banned within 10 s, later attempts blocked\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    int banned_at = 0;
    for (int i = 1; i <= 8; i++) {
        LoginEvent e = ev(T0 + i, "6.6.6.6", "admin", 0);
        detector_process(d, &e, &r);
        if (r.newly_banned) banned_at = i;
    }
    const IpRecord *rec = detector_get_ip(d, "6.6.6.6");
    CHECK(rec != NULL && rec->is_banned);
    CHECK(banned_at == 5);                       /* 12.5*5 + 5 = 67.5 >= 60 */
    CHECK(rec->flags & CAT_FAST);
    CHECK(rec->blocked_attempts == 3 && d->blocked_events == 3);
    CHECK(r.blocked && strcmp(r.label, "Blocked") == 0);
    CHECK(has_alert(d, "Fast brute-force", "6.6.6.6") && has_alert(d, "Blocked", "6.6.6.6"));
    CHECK(cq_active_count(d->bans) == 1);
    HeapItem top[3];
    CHECK(detector_top(d, 3, top) == 1 && strcmp(top[0].key, "6.6.6.6") == 0);
    CHECK(d->category_counts[0] == 1 && d->total_bans == 1);
    detector_destroy(d);
}

static void test_normal_user(void) {
    printf("normal user with two typos is not flagged\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    LoginEvent e = ev(T0, "10.0.0.5", "alice", 0); detector_process(d, &e, &r);
    CHECK(strcmp(r.label, "Failed login") == 0);
    e = ev(T0 + 4, "10.0.0.5", "alice", 0); detector_process(d, &e, &r);
    e = ev(T0 + 9, "10.0.0.5", "alice", 1); detector_process(d, &e, &r);
    CHECK(strcmp(r.label, "Normal") == 0);
    const IpRecord *rec = detector_get_ip(d, "10.0.0.5");
    CHECK(!rec->is_banned && rec->flags == 0 && rec->score < d->settings.score_threshold);
    CHECK(alert_list_size(d->alerts) == 0);
    CHECK(d->total_events == 3 && d->total_failed == 2 && d->total_success == 1);
    detector_destroy(d);
}

static void test_low_and_slow(void) {
    printf("low-and-slow: one failure every 90 s is flagged and banned, never 'fast'\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    int minute_banned = -1;
    for (int i = 0; i < 40; i++) {
        LoginEvent e = ev(T0 + i * 90, "7.7.7.7", "root", 0);
        detector_process(d, &e, &r);
        if (r.newly_banned && minute_banned < 0) minute_banned = i * 90 / 60;
    }
    const IpRecord *rec = detector_get_ip(d, "7.7.7.7");
    CHECK(rec->ever_flags & CAT_SLOW);
    CHECK(!(rec->ever_flags & CAT_FAST));
    CHECK(rec->times_banned >= 1);
    CHECK(minute_banned > 10 && minute_banned < 40);
    printf("    (banned after about %d minutes)\n", minute_banned);
    detector_destroy(d);
}

static void test_credential_stuffing(void) {
    printf("credential stuffing: many usernames from one IP\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    char name[16];
    for (int i = 0; i < 12; i++) {
        snprintf(name, sizeof name, "user%02d", i);
        LoginEvent e = ev(T0 + i * 30, "8.8.4.4", name, 0);
        detector_process(d, &e, &r);
    }
    const IpRecord *rec = detector_get_ip(d, "8.8.4.4");
    CHECK(rec->ever_flags & CAT_STUFFING);
    CHECK(rec->times_banned >= 1);
    CHECK(has_alert(d, "Credential stuffing", "8.8.4.4"));
    detector_destroy(d);
}

static void test_distributed(void) {
    printf("distributed attack: many IPs, few attempts each, one username\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    char ip[32];
    long long t = T0;
    for (int round = 0; round < 4; round++)
        for (int k = 0; k < 8; k++) {
            snprintf(ip, sizeof ip, "203.0.113.%d", k + 1);
            LoginEvent e = ev(t, ip, "admin", 0);
            t += 20;                                 /* one attempt every 20 s overall */
            detector_process(d, &e, &r);
        }
    const UserStats *user = detector_get_user(d, "admin");
    CHECK(user != NULL && user->under_attack);
    CHECK(d->distributed_usernames == 1);
    int flagged = 0;
    for (int k = 0; k < 8; k++) {
        snprintf(ip, sizeof ip, "203.0.113.%d", k + 1);
        const IpRecord *rec = detector_get_ip(d, ip);
        if (rec->ever_flags & CAT_DISTRIBUTED) flagged++;
        CHECK(!(rec->ever_flags & CAT_FAST));          /* each IP is slow */
    }
    CHECK(flagged == 8);
    CHECK(has_alert(d, "Distributed attack", ""));
    detector_destroy(d);
}

static void test_ban_expiry(void) {
    printf("ban expires on the simulation clock\n");
    Settings s;
    settings_set_defaults(&s);
    s.ban_duration = 120;
    Detector *d = detector_create(&s);
    EventResult r;
    for (int i = 0; i < 5; i++) { LoginEvent e = ev(T0 + i, "1.2.3.4", "admin", 0); detector_process(d, &e, &r); }
    const IpRecord *rec = detector_get_ip(d, "1.2.3.4");
    CHECK(rec->is_banned && rec->ban_expires_at == T0 + 4 + 120);
    detector_tick(d, T0 + 4 + 119);
    CHECK(rec->is_banned);
    detector_tick(d, T0 + 4 + 120);
    CHECK(!rec->is_banned && cq_is_empty(d->bans));
    CHECK(has_alert(d, "Unblocked", "1.2.3.4"));
    /* after expiry a single new failure is accepted (not blocked) */
    LoginEvent e = ev(T0 + 200, "1.2.3.4", "admin", 0);
    detector_process(d, &e, &r);
    CHECK(!r.blocked);
    detector_destroy(d);
}

static void test_shorter_duration_keeps_order(void) {
    printf("shortening the ban duration never breaks expiry order\n");
    Detector *d = detector_create(NULL);           /* ban 300 s */
    EventResult r;
    for (int i = 0; i < 5; i++) { LoginEvent e = ev(T0 + i, "1.1.1.1", "admin", 0); detector_process(d, &e, &r); }
    Settings s = d->settings;
    s.ban_duration = 60;
    detector_apply_settings(d, &s);
    for (int i = 0; i < 5; i++) { LoginEvent e = ev(T0 + 10 + i, "2.2.2.2", "admin", 0); detector_process(d, &e, &r); }
    const IpRecord *a = detector_get_ip(d, "1.1.1.1");
    const IpRecord *b = detector_get_ip(d, "2.2.2.2");
    CHECK(a->is_banned && b->is_banned);
    CHECK(b->ban_expires_at >= a->ban_expires_at);  /* clamped, not out of order */
    CHECK(cq_size(d->bans) == 2);
    detector_tick(d, a->ban_expires_at);
    CHECK(!a->is_banned && !b->is_banned);          /* both end together */
    /* longer durations simply append */
    s.ban_duration = 600;
    detector_apply_settings(d, &s);
    for (int i = 0; i < 5; i++) { LoginEvent e = ev(T0 + 1000 + i, "3.3.3.3", "admin", 0); detector_process(d, &e, &r); }
    CHECK(detector_get_ip(d, "3.3.3.3")->ban_expires_at == T0 + 1004 + 600);
    detector_destroy(d);
}

static void test_manual_unblock(void) {
    printf("manual unblock (simulation)\n");
    Detector *d = detector_create(NULL);
    EventResult r;
    for (int i = 0; i < 5; i++) { LoginEvent e = ev(T0 + i, "9.9.9.9", "admin", 0); detector_process(d, &e, &r); }
    CHECK(detector_unblock(d, "9.9.9.9") == 1);
    CHECK(detector_unblock(d, "9.9.9.9") == 0);     /* not banned any more */
    CHECK(detector_unblock(d, "5.5.5.5") == 0);     /* unknown IP */
    const IpRecord *rec = detector_get_ip(d, "9.9.9.9");
    CHECK(!rec->is_banned && rec->score == 0.0 && !heap_contains(d->ranking, "9.9.9.9"));
    CHECK(cq_active_count(d->bans) == 0 && cq_size(d->bans) == 1);   /* lazy deletion */
    LoginEvent e = ev(T0 + 20, "9.9.9.9", "admin", 0);
    detector_process(d, &e, &r);
    CHECK(!r.blocked);
    detector_tick(d, T0 + 10000);
    CHECK(cq_size(d->bans) == 0);                   /* inactive entry dropped at expiry */
    detector_destroy(d);
}

static void test_decay(void) {
    printf("scores decay when an IP goes quiet\n");
    Settings s;
    settings_set_defaults(&s);
    s.score_threshold = 1000;                       /* never ban in this test */
    Detector *d = detector_create(&s);
    EventResult r;
    for (int i = 0; i < 6; i++) { LoginEvent e = ev(T0 + i, "4.4.4.4", "admin", 0); detector_process(d, &e, &r); }
    const IpRecord *rec = detector_get_ip(d, "4.4.4.4");
    double fresh = rec->score;
    detector_tick(d, T0 + 60);                      /* short window empty */
    CHECK(rec->score < fresh && rec->score > 0);
    double after_minute = rec->score;
    detector_tick(d, T0 + 900);                     /* medium window empty */
    CHECK(rec->score < after_minute && rec->score > 0);
    detector_tick(d, T0 + 4000);                    /* everything expired */
    CHECK(rec->score == 0.0 && rec->flags == 0 && (rec->ever_flags & CAT_FAST));
    CHECK(!heap_contains(d->ranking, "4.4.4.4"));
    detector_destroy(d);
}

static void test_misc(void) {
    printf("settings validation, out-of-order events, reset\n");
    Settings s;
    settings_set_defaults(&s);
    CHECK(settings_validate(&s) == 1);
    s.short_threshold = 0; s.ban_duration = -5; s.score_threshold = -1;
    CHECK(settings_validate(&s) == 0);
    CHECK(s.short_threshold == 1 && s.ban_duration == 10 && s.score_threshold == 1.0);

    Detector *d = detector_create(NULL);
    EventResult r;
    LoginEvent e = ev(T0 + 100, "1.1.1.1", "a", 1); detector_process(d, &e, &r);
    e = ev(T0 + 50, "1.1.1.1", "a", 1); detector_process(d, &e, &r);
    CHECK(d->out_of_order_events == 1 && d->now == T0 + 100);
    detector_process(d, NULL, &r);                  /* must not crash */
    CHECK(strcmp(category_primary_name(CAT_SLOW | CAT_FAST), "Fast brute-force") == 0);
    CHECK(strcmp(category_primary_name(0), "None") == 0);
    CHECK(strcmp(severity_for_score(70, 60), "critical") == 0);
    CHECK(strcmp(severity_for_score(10, 60), "low") == 0);
    CHECK(detector_reset(d) == 1);
    CHECK(d->total_events == 0 && ht_count(d->ips) == 0 && d->now == 0);
    detector_destroy(d);
    detector_destroy(NULL);
}

int main(void) {
    test_fast();
    test_normal_user();
    test_low_and_slow();
    test_credential_stuffing();
    test_distributed();
    test_ban_expiry();
    test_shorter_duration_keeps_order();
    test_manual_unblock();
    test_decay();
    test_misc();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
