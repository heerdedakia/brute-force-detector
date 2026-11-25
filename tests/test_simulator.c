/* Unit tests for the attack simulator. Run: make test_simulator */
#include <stdio.h>
#include <string.h>
#include "../backend/simulator.h"
#include "../backend/detector.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void test_rng(void) {
    printf("random generator is reproducible and in range\n");
    Rng a, b;
    rng_seed(&a, 42); rng_seed(&b, 42);
    int same = 1, in_range = 1;
    for (int i = 0; i < 10000; i++) {
        if (rng_next(&a) != rng_next(&b)) same = 0;
        int v = rng_range(&a, 3, 7);
        if (v < 3 || v > 7) in_range = 0;
        rng_next(&b);                                 /* keep b in step with a */
    }
    CHECK(same && in_range);
    rng_seed(&a, 0);                                  /* seed 0 must still work */
    CHECK(rng_next(&a) != rng_next(&a));
    CHECK(rng_range(&a, 5, 5) == 5 && rng_range(&a, 9, 2) == 9);
}

static void test_reproducible_and_sorted(void) {
    printf("same seed -> identical stream; output sorted by time\n");
    SimConfig c;
    EventList e1, e2;
    GroundTruth t1, t2;
    sim_config_defaults(&c);
    event_list_init(&e1); event_list_init(&e2);
    ground_truth_init(&t1); ground_truth_init(&t2);
    CHECK(sim_generate(&c, &e1, &t1) > 0);
    CHECK(sim_generate(&c, &e2, &t2) == e1.count);
    CHECK(memcmp(e1.items, e2.items, sizeof(LoginEvent) * (size_t)e1.count) == 0);
    CHECK(memcmp(t1.labels, t2.labels, sizeof(int) * (size_t)t1.count) == 0);
    CHECK(t1.count == e1.count);
    int sorted = 1;
    for (int i = 1; i < e1.count; i++) if (e1.items[i].timestamp < e1.items[i - 1].timestamp) sorted = 0;
    CHECK(sorted);
    c.seed = 7;
    sim_generate(&c, &e2, &t2);
    CHECK(e2.count != e1.count || memcmp(e1.items, e2.items, sizeof(LoginEvent) * (size_t)e1.count) != 0);
    event_list_free(&e1); event_list_free(&e2);
    ground_truth_free(&t1); ground_truth_free(&t2);
}

static void test_scenarios(void) {
    printf("each scenario has the right size, labels and IP range\n");
    const char *prefix[LABEL_COUNT] = {"10.", "185.220.", "45.83.", "91.240.", "198.51."};
    EventList ev;
    GroundTruth tr;
    event_list_init(&ev);
    ground_truth_init(&tr);
    for (int type = LABEL_NORMAL; type < LABEL_COUNT; type++) {
        SimConfig c;
        sim_config_defaults(&c);
        c.attack_type = type;
        c.attempts = 40;
        c.attacker_ips = type == LABEL_DISTRIBUTED ? 10 : 2;
        CHECK(sim_generate(&c, &ev, &tr) > 0);
        int attack_events = 0, label_ok = 1;
        for (int i = 0; i < ev.count; i++) {
            int label = tr.labels[i];
            if (label != LABEL_NORMAL) attack_events++;
            if (strncmp(ev.items[i].ip, prefix[label], strlen(prefix[label])) != 0) label_ok = 0;
            if (label != LABEL_NORMAL && label != type) label_ok = 0;
        }
        CHECK(label_ok);
        CHECK(attack_events == (type == LABEL_NORMAL ? 0 : 40));
    }
    event_list_free(&ev);
    ground_truth_free(&tr);
}

static void test_csv_round_trip(void) {
    printf("write CSV and read it back with the parser\n");
    SimConfig c;
    EventList ev, back;
    GroundTruth tr;
    ParseStats stats = {0, 0, 0, 0, 0};
    sim_config_defaults(&c);
    event_list_init(&ev); event_list_init(&back); ground_truth_init(&tr);
    sim_generate(&c, &ev, &tr);
    CHECK(sim_write_csv(&ev, "test_sim_tmp.csv", "simulated events"));
    CHECK(parse_file("test_sim_tmp.csv", &back, &stats) == ev.count);
    CHECK(stats.malformed == 0 && stats.ignored == 1);
    CHECK(memcmp(ev.items, back.items, sizeof(LoginEvent) * (size_t)ev.count) == 0);
    remove("test_sim_tmp.csv");
    event_list_free(&ev); event_list_free(&back); ground_truth_free(&tr);
}

static void test_detector_sees_attacks(void) {
    printf("detector run on simulated streams (ground truth used only here)\n");
    for (int type = LABEL_FAST; type < LABEL_COUNT; type++) {
        SimConfig c;
        EventList ev;
        GroundTruth tr;
        sim_config_defaults(&c);
        c.attack_type = type;
        c.attempts = type == LABEL_DISTRIBUTED ? 80 : 40;
        c.attacker_ips = type == LABEL_DISTRIBUTED ? 16 : 2;
        event_list_init(&ev); ground_truth_init(&tr);
        sim_generate(&c, &ev, &tr);
        Detector *d = detector_create(NULL);
        for (int i = 0; i < ev.count; i++) detector_process(d, &ev.items[i], NULL);  /* no labels! */
        int attackers = 0, flagged = 0;
        for (int i = 0; i < ev.count; i++) {
            if (tr.labels[i] == LABEL_NORMAL) continue;
            const IpRecord *rec = detector_get_ip(d, ev.items[i].ip);
            if (rec->first_seen == ev.items[i].timestamp) {     /* count each IP once */
                attackers++;
                if (rec->ever_flags || rec->times_banned) flagged++;
            }
        }
        printf("    %-20s %d/%d attacker IPs flagged\n", sim_label_name(type), flagged, attackers);
        CHECK(attackers > 0 && flagged == attackers);
        detector_destroy(d);
        event_list_free(&ev); ground_truth_free(&tr);
    }
}

static void test_mixed(void) {
    printf("mixed scenario contains every label\n");
    SimConfig c;
    EventList ev;
    GroundTruth tr;
    int seen[LABEL_COUNT] = {0};
    sim_config_defaults(&c);
    c.attack_type = SIM_MIXED;
    event_list_init(&ev); ground_truth_init(&tr);
    CHECK(sim_generate(&c, &ev, &tr) > 0);
    for (int i = 0; i < tr.count; i++) seen[tr.labels[i]]++;
    for (int l = 0; l < LABEL_COUNT; l++) CHECK(seen[l] > 0);
    CHECK(strcmp(sim_label_name(SIM_MIXED), "Mixed (all attacks)") == 0);
    event_list_free(&ev); ground_truth_free(&tr);
}

int main(void) {
    test_mixed();
    test_rng();
    test_reproducible_and_sorted();
    test_scenarios();
    test_csv_round_trip();
    test_detector_sees_attacks();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
