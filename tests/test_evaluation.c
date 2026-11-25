/* Unit tests for the baseline detector and the evaluator. Run: make test_evaluation */
#include <stdio.h>
#include <string.h>
#include "../backend/baseline.h"
#include "../backend/evaluation.h"
#include "../backend/detector.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

#define T0 1795177815LL

static LoginEvent ev(long long t, const char *ip, int success) {
    LoginEvent e;
    memset(&e, 0, sizeof e);
    e.timestamp = t;
    strcpy(e.ip, ip);
    strcpy(e.username, "admin");
    e.success = success;
    return e;
}

static void test_baseline_rule(void) {
    printf("baseline: 5 failures in 60 s -> ban; slower attacks pass\n");
    BaselineDetector *b = baseline_create(300);
    for (int i = 0; i < 4; i++) { LoginEvent e = ev(T0 + i * 10, "1.1.1.1", 0); baseline_process(b, &e); }
    CHECK(baseline_get(b, "1.1.1.1")->times_banned == 0);          /* only 4 */
    LoginEvent e = ev(T0 + 50, "1.1.1.1", 0);
    baseline_process(b, &e);
    CHECK(baseline_get(b, "1.1.1.1")->is_banned);                   /* 5th within 60 s */
    e = ev(T0 + 51, "1.1.1.1", 0);
    CHECK(baseline_process(b, &e) == 1 && b->blocked_events == 1);
    e = ev(T0 + 50 + 300, "1.1.1.1", 0);                            /* ban over */
    CHECK(baseline_process(b, &e) == 0);

    for (int i = 0; i < 100; i++) {                                 /* one try every 15 s */
        e = ev(T0 + i * 15, "2.2.2.2", 0);
        baseline_process(b, &e);
    }
    CHECK(baseline_get(b, "2.2.2.2")->times_banned == 0);           /* never 5 in 60 s */
    for (int i = 0; i < 20; i++) { e = ev(T0 + i, "3.3.3.3", 1); baseline_process(b, &e); }
    CHECK(baseline_get(b, "3.3.3.3")->times_banned == 0);           /* successes ignored */
    CHECK(baseline_get(b, "9.9.9.9") == NULL);
    CHECK(baseline_process(NULL, &e) == 0 && baseline_process(b, NULL) == 0);
    baseline_destroy(b);
}

static void test_evaluation(void) {
    printf("evaluation produces consistent, reproducible numbers\n");
    Settings s;
    settings_set_defaults(&s);
    EvalResults a, b;
    CHECK(evaluation_run(&s, 77, 2, 20000, &a) == 1);
    CHECK(evaluation_run(&s, 77, 2, 20000, &b) == 1);
    CHECK(a.valid && a.runs == 8 && a.throughput_events == 20000);
    int counts_ok = 1, same = 1;
    for (int l = 0; l < LABEL_COUNT; l++) {
        if (a.proposed_detected[l] > a.ip_count[l] || a.proposed_correct[l] > a.proposed_detected[l] ||
            a.proposed_blocked[l] > a.ip_count[l] || a.baseline_detected[l] > a.ip_count[l]) counts_ok = 0;
        if (a.proposed_detected[l] != b.proposed_detected[l] || a.ip_count[l] != b.ip_count[l] ||
            a.baseline_detected[l] != b.baseline_detected[l]) same = 0;    /* timing may differ, counts may not */
    }
    CHECK(counts_ok && same);
    CHECK(a.ip_count[LABEL_FAST] == 6 && a.ip_count[LABEL_DISTRIBUTED] == 40);
    CHECK(a.ip_count[LABEL_NORMAL] > 0);
    /* the claims the project makes - checked, not assumed */
    CHECK(a.baseline_detected[LABEL_FAST] == a.ip_count[LABEL_FAST]);       /* baseline catches fast  */
    CHECK(a.baseline_detected[LABEL_SLOW] == 0);                            /* ...but not slow        */
    CHECK(a.proposed_detected[LABEL_SLOW] == a.ip_count[LABEL_SLOW]);
    CHECK(a.proposed_detected[LABEL_DISTRIBUTED] == a.ip_count[LABEL_DISTRIBUTED]);
    CHECK(a.proposed_eps > 0 && a.baseline_eps > 0);
    CHECK(eval_rate(1, 4) == 0.25 && eval_rate(3, 0) == 0.0);
    CHECK(evaluation_run(NULL, 1, 1, 1000, &a) == 0);
    evaluation_print(&b);
}

int main(void) {
    test_baseline_rule();
    test_evaluation();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
