/* Unit tests for the circular-array deque. Run: make test_deque */
#include <stdio.h>
#include "../backend/deque.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void test_basic(void) {
    printf("basic push/pop/peek\n");
    Deque *dq = deque_create(4);
    long long v;
    CHECK(dq != NULL);
    CHECK(deque_is_empty(dq));
    CHECK(!deque_pop_front(dq, &v));          /* pop on empty fails */
    CHECK(!deque_peek_front(dq, &v));
    deque_push_rear(dq, 10); deque_push_rear(dq, 20); deque_push_rear(dq, 30);
    CHECK(deque_size(dq) == 3);
    CHECK(deque_peek_front(dq, &v) && v == 10);
    CHECK(deque_peek_rear(dq, &v) && v == 30);
    CHECK(deque_pop_front(dq, &v) && v == 10);
    CHECK(deque_pop_front(dq, &v) && v == 20);
    CHECK(deque_size(dq) == 1);
    deque_destroy(dq);
}

static void test_wraparound(void) {
    printf("wrap-around\n");
    Deque *dq = deque_create(4);
    long long v;
    deque_push_rear(dq, 1); deque_push_rear(dq, 2); deque_push_rear(dq, 3);
    deque_pop_front(dq, &v); deque_pop_front(dq, &v);   /* front is now index 2 */
    deque_push_rear(dq, 4); deque_push_rear(dq, 5); deque_push_rear(dq, 6);
    CHECK(deque_is_full(dq));
    CHECK(dq->capacity == 4);                           /* no growth needed */
    CHECK(dq->front == 2);                              /* data wraps around */
    for (long long expect = 3; expect <= 6; expect++)
        CHECK(deque_pop_front(dq, &v) && v == expect);
    CHECK(deque_is_empty(dq));
    deque_destroy(dq);
}

static void test_expansion(void) {
    printf("capacity expansion keeps order\n");
    Deque *dq = deque_create(2);
    long long v;
    deque_push_rear(dq, 1); deque_push_rear(dq, 2);
    deque_pop_front(dq, &v);
    deque_push_rear(dq, 3);                 /* wrapped and full */
    deque_push_rear(dq, 4);                 /* forces expansion */
    CHECK(dq->capacity == 4);
    for (long long i = 5; i <= 100; i++) deque_push_rear(dq, i);
    CHECK(deque_size(dq) == 99);
    for (long long expect = 2; expect <= 100; expect++)
        CHECK(deque_pop_front(dq, &v) && v == expect);
    CHECK(deque_is_empty(dq));
    deque_destroy(dq);
}

static void test_window_expiry(void) {
    printf("sliding-window expiry\n");
    Deque *dq = deque_create(4);
    long long v;
    for (long long t = 100; t <= 150; t += 10) deque_push_rear(dq, t); /* 100..150 */
    CHECK(deque_remove_older_than(dq, 120) == 2);       /* removes 100, 110 */
    CHECK(deque_peek_front(dq, &v) && v == 120);
    CHECK(deque_remove_older_than(dq, 120) == 0);       /* nothing more */
    CHECK(deque_remove_older_than(dq, 1000) == 4);      /* removes everything */
    CHECK(deque_is_empty(dq));
    deque_destroy(dq);
}

static void test_edge_cases(void) {
    printf("edge cases\n");
    CHECK(deque_is_empty(NULL));
    CHECK(deque_size(NULL) == 0);
    CHECK(!deque_push_rear(NULL, 1));
    deque_destroy(NULL);                                /* must not crash */
    Deque *dq = deque_create(0);                        /* bad capacity fixed to 1 */
    CHECK(dq != NULL && dq->capacity == 1);
    CHECK(deque_push_rear(dq, 7) && deque_push_rear(dq, 8));
    deque_destroy(dq);
}

int main(void) {
    test_basic(); test_wraparound(); test_expansion();
    test_window_expiry(); test_edge_cases();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
