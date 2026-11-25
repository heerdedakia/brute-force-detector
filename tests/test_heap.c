/* Unit tests for the max heap with index map. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../backend/heap.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void test_order(void) {
    printf("insert and extract in descending order\n");
    MaxHeap *h = heap_create(2);
    HeapItem item;
    CHECK(!heap_extract_max(h, &item));              /* empty */
    heap_set(h, "a", 5); heap_set(h, "b", 50); heap_set(h, "c", 20);
    heap_set(h, "d", 35); heap_set(h, "e", 1);
    CHECK(heap_size(h) == 5 && heap_check_invariants(h));
    CHECK(heap_peek_max(h, &item) && strcmp(item.key, "b") == 0);
    const char *expected[] = {"b", "d", "c", "a", "e"};
    for (int i = 0; i < 5; i++) {
        CHECK(heap_extract_max(h, &item) && strcmp(item.key, expected[i]) == 0);
        CHECK(heap_check_invariants(h));
    }
    CHECK(heap_size(h) == 0);
    heap_destroy(h);
}

static void test_update(void) {
    printf("update priority up and down\n");
    MaxHeap *h = heap_create(4);
    HeapItem item; double p;
    heap_set(h, "ip1", 10); heap_set(h, "ip2", 20); heap_set(h, "ip3", 30);
    heap_set(h, "ip1", 99);                          /* raise: must become the max */
    CHECK(heap_peek_max(h, &item) && strcmp(item.key, "ip1") == 0);
    CHECK(heap_check_invariants(h));
    heap_set(h, "ip1", 5);                           /* lower: must sink to the bottom */
    CHECK(heap_peek_max(h, &item) && strcmp(item.key, "ip3") == 0);
    CHECK(heap_get_priority(h, "ip1", &p) && p == 5);
    CHECK(heap_size(h) == 3);                        /* updates do not add items */
    CHECK(heap_check_invariants(h));
    CHECK(!heap_get_priority(h, "nope", &p));
    heap_destroy(h);
}

static void test_remove_and_topk(void) {
    printf("remove by key and top-k\n");
    MaxHeap *h = heap_create(4);
    char key[16];
    for (int i = 1; i <= 12; i++) { sprintf(key, "ip%d", i); heap_set(h, key, i * 10.0); }
    HeapItem top[10];
    int n = heap_top_k(h, 10, top);
    CHECK(n == 10);
    CHECK(strcmp(top[0].key, "ip12") == 0 && strcmp(top[9].key, "ip3") == 0);
    CHECK(heap_size(h) == 12 && heap_check_invariants(h));   /* heap untouched */
    CHECK(heap_remove(h, "ip12"));
    CHECK(heap_remove(h, "ip5"));                    /* from the middle */
    CHECK(!heap_remove(h, "ip5"));
    CHECK(!heap_contains(h, "ip5") && heap_contains(h, "ip6"));
    CHECK(heap_size(h) == 10 && heap_check_invariants(h));
    CHECK(heap_top_k(h, 3, top) == 3 && strcmp(top[0].key, "ip11") == 0);
    CHECK(heap_top_k(h, 10, top) == 10);             /* heap holds exactly 10 now */
    heap_destroy(h);
}

static void test_edge_cases(void) {
    printf("edge cases\n");
    char too_long[100];
    memset(too_long, 'z', 99); too_long[99] = '\0';
    MaxHeap *h = heap_create(0);
    CHECK(h != NULL);
    CHECK(!heap_set(h, too_long, 1.0));
    CHECK(heap_size(h) == 0 && heap_check_invariants(h));
    CHECK(heap_set(h, "x", 7) && heap_set(h, "y", 7)); /* ties are fine */
    CHECK(heap_check_invariants(h));
    CHECK(!heap_peek_max(NULL, NULL));
    heap_destroy(h);
    heap_destroy(NULL);
}

/* Random stress test: compare the heap against a plain array. */
static void test_random_stress(void) {
    printf("random stress (20000 operations vs naive array)\n");
    enum { KEYS = 200 };
    double naive[KEYS]; int present[KEYS] = {0};
    MaxHeap *h = heap_create(4);
    char key[16];
    int all_ok = 1;
    srand(12345);
    for (int op = 0; op < 20000; op++) {
        int k = rand() % KEYS;
        sprintf(key, "ip%d", k);
        int action = rand() % 4;
        if (action <= 1) {                           /* set (insert or update) */
            double score = (double)(rand() % 1000);
            heap_set(h, key, score); naive[k] = score; present[k] = 1;
        } else if (action == 2) {                    /* remove */
            int removed = heap_remove(h, key);
            if (removed != present[k]) all_ok = 0;
            present[k] = 0;
        } else {                                     /* extract max */
            HeapItem item;
            double best = -1;
            for (int i = 0; i < KEYS; i++) if (present[i] && naive[i] > best) best = naive[i];
            if (heap_extract_max(h, &item)) {
                if (item.priority != best) all_ok = 0;
                present[atoi(item.key + 2)] = 0;
            } else if (best >= 0) all_ok = 0;
        }
        if (!heap_check_invariants(h)) all_ok = 0;
    }
    CHECK(all_ok);
    heap_destroy(h);
}

int main(void) {
    test_order(); test_update(); test_remove_and_topk();
    test_edge_cases(); test_random_stress();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
