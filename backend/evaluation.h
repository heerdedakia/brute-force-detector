/*
 * evaluation.h - compares the proposed multi-window detector with the
 * single-rule baseline on the SAME labelled, simulated streams.
 *
 * Every number produced here comes from actually running both detectors.
 * Nothing is typed in by hand.
 */
#ifndef EVALUATION_H
#define EVALUATION_H

#include "settings.h"
#include "simulator.h"

typedef struct {
    /* index = true label (LABEL_NORMAL .. LABEL_DISTRIBUTED) */
    int ip_count[LABEL_COUNT];            /* IPs with that true label (summed over runs) */
    int proposed_detected[LABEL_COUNT];   /* flagged with any category OR banned          */
    int proposed_correct[LABEL_COUNT];    /* flagged with the MATCHING category            */
    int proposed_blocked[LABEL_COUNT];    /* banned at least once                          */
    int baseline_detected[LABEL_COUNT];   /* baseline banned it (its only action)          */
    double proposed_delay[LABEL_COUNT];   /* avg seconds from IP's first event to detection */
    double baseline_delay[LABEL_COUNT];

    int runs;                             /* simulated streams evaluated                    */
    long long accuracy_events;            /* events in those streams                        */

    long long throughput_events;          /* events in the timing replay                    */
    double proposed_seconds, baseline_seconds;
    double proposed_eps, baseline_eps;    /* events per second                              */

    Settings settings_used;
    unsigned long long base_seed;
    int valid;                            /* 1 after a successful run                       */
} EvalResults;

/* seeds: number of different random seeds per attack type (e.g. 5).
 * throughput_events: size of the timing replay (e.g. 300000).
 * Returns 1 ok, 0 out of memory. */
int evaluation_run(const Settings *settings, unsigned long long base_seed, int seeds,
                   int throughput_events, EvalResults *out);

/* Detection rate helpers: value in 0..1 (0 when there were no IPs). */
double eval_rate(int part, int whole);

/* Prints a readable table to stdout (used by "detector --evaluate"). */
void evaluation_print(const EvalResults *r);

#endif
