/* Unit tests for the separate-chaining hash table. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../backend/hashtable.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void count_visit(const char *key, void *value, void *context) {
    (void)key; (void)value;
    (*(int *)context)++;
}

static void test_basic(void) {
    printf("put/get/update/remove\n");
    HashTable *t = ht_create(8);
    int a = 1, b = 2, c = 3;
    void *removed = NULL;
    CHECK(ht_put(t, "10.0.0.1", &a));
    CHECK(ht_put(t, "10.0.0.2", &b));
    CHECK(ht_get(t, "10.0.0.1") == &a);
    CHECK(ht_get(t, "10.0.0.2") == &b);
    CHECK(ht_get(t, "missing") == NULL);
    CHECK(ht_count(t) == 2);
    CHECK(ht_put(t, "10.0.0.1", &c));               /* update, count unchanged */
    CHECK(ht_get(t, "10.0.0.1") == &c && ht_count(t) == 2);
    CHECK(ht_remove(t, "10.0.0.1", &removed) && removed == &c);
    CHECK(!ht_contains(t, "10.0.0.1"));
    CHECK(!ht_remove(t, "10.0.0.1", NULL));          /* already gone */
    CHECK(ht_count(t) == 1);
    ht_destroy(t, NULL);
}

static void test_collisions(void) {
    printf("collisions (starts with 1 bucket, so chains are long)\n");
    HashTable *t = ht_create(1);
    int values[5] = {0, 1, 2, 3, 4};
    char key[16];
    for (int i = 0; i < 5; i++) { sprintf(key, "k%d", i); CHECK(ht_put(t, key, &values[i])); }
    for (int i = 0; i < 5; i++) { sprintf(key, "k%d", i); CHECK(ht_get(t, key) == &values[i]); }
    CHECK(ht_remove(t, "k2", NULL));                 /* middle of a chain */
    CHECK(ht_get(t, "k1") == &values[1] && ht_get(t, "k3") == &values[3]);
    CHECK(ht_count(t) == 4);
    ht_destroy(t, NULL);
}

static void test_resize_many(void) {
    printf("resize with 5000 keys\n");
    HashTable *t = ht_create(4);
    char key[32];
    for (int i = 0; i < 5000; i++) {
        sprintf(key, "192.168.%d.%d", i / 256, i % 256);
        int *v = malloc(sizeof(int)); *v = i;
        CHECK(ht_put(t, key, v));
    }
    CHECK(ht_count(t) == 5000);
    CHECK(t->bucket_count > 4);
    CHECK(t->count * 4 <= t->bucket_count * 3);      /* load factor respected */
    int ok = 1;
    for (int i = 0; i < 5000; i++) {
        sprintf(key, "192.168.%d.%d", i / 256, i % 256);
        int *v = ht_get(t, key);
        if (v == NULL || *v != i) ok = 0;
    }
    CHECK(ok);
    int visited = 0;
    ht_for_each(t, count_visit, &visited);
    CHECK(visited == 5000);
    for (int i = 0; i < 5000; i += 2) {              /* remove half, free values */
        void *removed;
        sprintf(key, "192.168.%d.%d", i / 256, i % 256);
        if (ht_remove(t, key, &removed)) free(removed);
    }
    CHECK(ht_count(t) == 2500);
    ht_destroy(t, free);                             /* frees remaining values */
}

static void test_edge_cases(void) {
    printf("edge cases\n");
    char too_long[100];
    memset(too_long, 'x', 99); too_long[99] = '\0';
    HashTable *t = ht_create(0);                     /* fixed to 1 bucket */
    CHECK(t != NULL);
    CHECK(!ht_put(t, too_long, NULL));
    CHECK(!ht_put(t, NULL, NULL));
    CHECK(ht_get(NULL, "a") == NULL);
    CHECK(ht_count(NULL) == 0);
    CHECK(ht_put(t, "", NULL));                      /* empty key is allowed */
    CHECK(ht_contains(t, ""));
    ht_destroy(t, NULL);
    ht_destroy(NULL, NULL);
}

int main(void) {
    test_basic(); test_collisions(); test_resize_many(); test_edge_cases();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
