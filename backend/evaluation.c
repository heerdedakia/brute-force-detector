/*
 * evaluation.c - accuracy and speed comparison (see evaluation.h).
 *
 * ACCURACY: for every attack type and every seed, one stream is generated
 * (normal background traffic + that attack). Both detectors read the events;
 * only afterwards do we look at the ground-truth labels to count:
 *   detection rate  = attacker IPs detected / attacker IPs
 *   false positives = normal IPs detected   / normal IPs
 * "Detected" for the proposed detector = any category alert or a ban.
 * "Detected" for the baseline          = a ban (it has nothing else).
 *
 * SPEED: one large stream is replayed through each detector and timed with
 * platform_seconds() (QueryPerformanceCounter on Windows).
 */
#include <stdio.h>
#include <string.h>
#include "evaluation.h"
#include "detector.h"
#include "baseline.h"
#include "platform.h"
#include "hashtable.h"

double eval_rate(int part, int whole) {
    return whole > 0 ? (double)part / (double)whole : 0.0;
}

static int category_bit_for_label(int label) {
    switch (label) {
    case LABEL_FAST:        return CAT_FAST;
    case LABEL_SLOW:        return CAT_SLOW;
    case LABEL_STUFFING:    return CAT_STUFFING;
    case LABEL_DISTRIBUTED: return CAT_DISTRIBUTED;
    default:                return 0;
    }
}

/* Sizes of each attack in the accuracy runs. */
static void config_for(int type, unsigned long long seed, SimConfig *c) {
    sim_config_defaults(c);
    c->attack_type = type;
    c->seed = seed;
    switch (type) {
    case LABEL_FAST:        c->attempts = 120; c->attacker_ips = 3;  break;  /* 40 per IP */
    case LABEL_SLOW:        c->attempts = 75;  c->attacker_ips = 3;  break;  /* 25 per IP */
    case LABEL_STUFFING:    c->attempts = 90;  c->attacker_ips = 3;  break;  /* 30 per IP */
    case LABEL_DISTRIBUTED: c->attempts = 100; c->attacker_ips = 20; break;  /*  5 per IP */
    default: break;
    }
}

/* Sums for the delay averages */
typedef struct {
    double proposed_total[LABEL_COUNT];
    double baseline_total[LABEL_COUNT];
    int baseline_count[LABEL_COUNT];
    int proposed_count[LABEL_COUNT];
} DelaySums;

/* Score one finished run: walk the events, look at each IP once. */
static void score_run(const EventList *ev, const GroundTruth *tr, const Detector *d,
                      const BaselineDetector *b, EvalResults *r, DelaySums *sums) {
    HashTable *seen = ht_create(64);       /* IPs already counted in this run */
    if (seen == NULL) return;
    for (int i = 0; i < ev->count; i++) {
        const char *ip = ev->items[i].ip;
        if (ht_contains(seen, ip)) continue;
        ht_put(seen, ip, NULL);

        int label = tr->labels[i];
        const IpRecord *p = detector_get_ip(d, ip);
        const BaselineRecord *q = baseline_get(b, ip);
        r->ip_count[label]++;

        if (p != NULL && (p->ever_flags || p->times_banned)) {
            r->proposed_detected[label]++;
            if (p->first_alert_at > 0) {
                sums->proposed_total[label] += (double)(p->first_alert_at - p->first_seen);
                sums->proposed_count[label]++;
            }
        }
        if (p != NULL && (p->ever_flags & category_bit_for_label(label))) r->proposed_correct[label]++;
        if (p != NULL && p->times_banned) r->proposed_blocked[label]++;
        if (q != NULL && q->times_banned) {
            r->baseline_detected[label]++;
            sums->baseline_total[label] += (double)(q->first_ban_at - q->first_seen);
            sums->baseline_count[label]++;
        }
    }
    ht_destroy(seen, NULL);
}

static int accuracy_runs(const Settings *s, unsigned long long base_seed, int seeds, EvalResults *r) {
    DelaySums sums;
    memset(&sums, 0, sizeof sums);
    EventList ev;
    GroundTruth tr;
    event_list_init(&ev);
    ground_truth_init(&tr);

    for (int seed = 0; seed < seeds; seed++) {
        for (int type = LABEL_FAST; type < LABEL_COUNT; type++) {
            SimConfig c;
            config_for(type, base_seed + (unsigned long long)(seed * 10 + type), &c);
            if (sim_generate(&c, &ev, &tr) < 0) goto out_of_memory;

            Detector *d = detector_create(s);
            BaselineDetector *b = baseline_create(s->ban_duration);
            if (d == NULL || b == NULL) {
                detector_destroy(d);
                baseline_destroy(b);
                goto out_of_memory;
            }
            /* The detectors receive ONLY the events. Labels stay in tr. */
            for (int i = 0; i < ev.count; i++) {
                detector_process(d, &ev.items[i], NULL);
                baseline_process(b, &ev.items[i]);
            }
            score_run(&ev, &tr, d, b, r, &sums);
            r->runs++;
            r->accuracy_events += ev.count;
            detector_destroy(d);
            baseline_destroy(b);
        }
    }
    for (int l = 0; l < LABEL_COUNT; l++) {
        r->proposed_delay[l] = sums.proposed_count[l] ? sums.proposed_total[l] / sums.proposed_count[l] : 0.0;
        r->baseline_delay[l] = sums.baseline_count[l] ? sums.baseline_total[l] / sums.baseline_count[l] : 0.0;
    }
    event_list_free(&ev);
    ground_truth_free(&tr);
    return 1;

out_of_memory:
    event_list_free(&ev);
    ground_truth_free(&tr);
    return 0;
}

/* Build a big stream by repeating a mixed scenario, shifted in time. */
static int build_replay(unsigned long long seed, int target, EventList *big) {
    SimConfig c;
    EventList unit;
    GroundTruth unit_truth;
    sim_config_defaults(&c);
    c.attack_type = SIM_MIXED;
    c.normal_users = 150;
    c.attacker_ips = 12;
    c.seed = seed;
    event_list_init(&unit);
    ground_truth_init(&unit_truth);
    if (sim_generate(&c, &unit, &unit_truth) <= 0) {
        event_list_free(&unit);
        ground_truth_free(&unit_truth);
        return 0;
    }
    long long span = unit.items[unit.count - 1].timestamp - unit.items[0].timestamp + 3600;
    for (int copy = 0; big->count < target; copy++) {
        for (int i = 0; i < unit.count && big->count < target; i++) {
            LoginEvent e = unit.items[i];
            e.timestamp += span * copy;
            if (!event_list_add(big, &e)) {
                event_list_free(&unit);
                ground_truth_free(&unit_truth);
                return 0;
            }
        }
    }
    event_list_free(&unit);
    ground_truth_free(&unit_truth);
    return 1;
}

static int throughput_run(const Settings *s, unsigned long long seed, int target, EvalResults *r) {
    EventList big;
    event_list_init(&big);
    if (target < 1000) target = 1000;
    if (!build_replay(seed, target, &big)) {
        event_list_free(&big);
        return 0;
    }
    Detector *d = detector_create(s);
    BaselineDetector *b = baseline_create(s->ban_duration);
    if (d == NULL || b == NULL) {
        detector_destroy(d);
        baseline_destroy(b);
        event_list_free(&big);
        return 0;
    }
    double start = platform_seconds();
    for (int i = 0; i < big.count; i++) detector_process(d, &big.items[i], NULL);
    double middle = platform_seconds();
    for (int i = 0; i < big.count; i++) baseline_process(b, &big.items[i]);
    double end = platform_seconds();

    r->throughput_events = big.count;
    r->proposed_seconds = middle - start;
    r->baseline_seconds = end - middle;
    r->proposed_eps = r->proposed_seconds > 0 ? big.count / r->proposed_seconds : 0.0;
    r->baseline_eps = r->baseline_seconds > 0 ? big.count / r->baseline_seconds : 0.0;

    detector_destroy(d);
    baseline_destroy(b);
    event_list_free(&big);
    return 1;
}

int evaluation_run(const Settings *settings, unsigned long long base_seed, int seeds,
                   int throughput_events, EvalResults *out) {
    if (settings == NULL || out == NULL) return 0;
    memset(out, 0, sizeof *out);
    out->settings_used = *settings;
    out->base_seed = base_seed;
    if (seeds < 1) seeds = 1;
    if (!accuracy_runs(settings, base_seed, seeds, out)) return 0;
    if (!throughput_run(settings, base_seed, throughput_events, out)) return 0;
    out->valid = 1;
    return 1;
}

void evaluation_print(const EvalResults *r) {
    printf("\nEvaluation: %d simulated runs, %lld events (seed base %llu)\n",
           r->runs, r->accuracy_events, r->base_seed);
    printf("%-22s %6s | %-27s | %-18s\n", "", "IPs", "Proposed: detect/correct/blk", "Baseline: detect");
    for (int l = LABEL_FAST; l < LABEL_COUNT; l++) {
        printf("%-22s %6d | %7.1f%% %7.1f%% %7.1f%%  | %7.1f%%\n", sim_label_name(l), r->ip_count[l],
               100 * eval_rate(r->proposed_detected[l], r->ip_count[l]),
               100 * eval_rate(r->proposed_correct[l], r->ip_count[l]),
               100 * eval_rate(r->proposed_blocked[l], r->ip_count[l]),
               100 * eval_rate(r->baseline_detected[l], r->ip_count[l]));
    }
    printf("%-22s %6d | FP %5.2f%% (blocked %5.2f%%)    | FP %5.2f%%\n", "Normal IPs (false pos.)",
           r->ip_count[LABEL_NORMAL],
           100 * eval_rate(r->proposed_detected[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]),
           100 * eval_rate(r->proposed_blocked[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]),
           100 * eval_rate(r->baseline_detected[LABEL_NORMAL], r->ip_count[LABEL_NORMAL]));
    printf("Mean time from an attacker's first attempt to detection (proposed / baseline):\n");
    for (int l = LABEL_FAST; l < LABEL_COUNT; l++) {
        printf("  %-22s %6.0f s / ", sim_label_name(l), r->proposed_delay[l]);
        if (r->baseline_detected[l] > 0) printf("%.0f s\n", r->baseline_delay[l]);
        else printf("never detected\n");
    }
    printf("Throughput on %lld events: proposed %.0f events/s (%.3f s), baseline %.0f events/s (%.3f s)\n\n",
           r->throughput_events, r->proposed_eps, r->proposed_seconds, r->baseline_eps, r->baseline_seconds);
}
