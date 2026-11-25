/*
 * simulator.h - seeded, reproducible generator of LABELLED login events.
 *
 * The same seed always produces exactly the same events, so every
 * demonstration and every benchmark can be repeated.
 *
 * Ground truth: the true label of every event ("this was a fast bot") goes
 * into a SEPARATE GroundTruth array. Only the evaluator reads it. The detector
 * only ever receives the LoginEvent array, so it cannot cheat.
 */
#ifndef SIMULATOR_H
#define SIMULATOR_H

#include "parser.h"

typedef enum {
    LABEL_NORMAL = 0,
    LABEL_FAST,
    LABEL_SLOW,
    LABEL_STUFFING,
    LABEL_DISTRIBUTED,
    LABEL_COUNT
} AttackLabel;

/* Not a label: asks sim_generate for ALL four attacks at once. */
#define SIM_MIXED LABEL_COUNT

typedef struct {
    int *labels;          /* labels[i] belongs to events.items[i] */
    int count;
    int capacity;
} GroundTruth;

typedef struct {
    int attack_type;            /* AttackLabel, LABEL_NORMAL = background only,
                                   or SIM_MIXED = all four attacks together      */
    int attempts;               /* total attack attempts (all attacker IPs)    */
    int attacker_ips;           /* how many attacker IPs                        */
    char target_username[EVENT_USER_MAX];
    int normal_users;           /* background users with their own IP           */
    int include_office_nat;     /* 1 = add one shared office IP with 8 users     */
    int background_seconds;     /* minimum length of background traffic         */
    long long start_time;       /* epoch seconds of the first event             */
    unsigned long long seed;
} SimConfig;

/* Small, portable random number generator (xorshift64*). We do not use
 * rand() because its sequence differs between Windows and Linux. */
typedef struct { unsigned long long state; } Rng;
void rng_seed(Rng *rng, unsigned long long seed);
unsigned int rng_next(Rng *rng);
int rng_range(Rng *rng, int low, int high);          /* inclusive both ends */

void sim_config_defaults(SimConfig *config);
const char *sim_label_name(int label);               /* "Normal", "Fast brute-force", ... */

void ground_truth_init(GroundTruth *truth);
void ground_truth_free(GroundTruth *truth);

/* Generates background traffic + the chosen attack, sorted by time.
 * events and truth are cleared first. Returns the number of events, or -1
 * if memory ran out. */
int sim_generate(const SimConfig *config, EventList *events, GroundTruth *truth);

/* Writes events as CSV lines (no labels). Returns 1 ok, 0 on file error. */
int sim_write_csv(const EventList *events, const char *path, const char *header_comment);

#endif
