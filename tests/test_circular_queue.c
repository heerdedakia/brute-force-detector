/* Unit tests for the circular queue of bans. Run: make test_circular_queue */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../backend/circular_queue.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static BanEntry make_ban(const char *ip, long long at, long long until) {
    BanEntry b;
    memset(&b, 0, sizeof(b));
    strcpy(b.ip, ip);
    strcpy(b.reason, "test");
    b.score = 50.0;
    b.blocked_at = at;
    b.expires_at = until;
    b.active = 1;
    return b;
}

static void test_basic(void) {
    printf("enqueue / dequeue / peek / full / empty\n");
    CircularQueue *q = cq_create(3);
    BanEntry b, out;
    CHECK(q != NULL && cq_is_empty(q));
    CHECK(!cq_dequeue(q, &out) && !cq_peek(q, &out));
    b = make_ban("1.1.1.1", 0, 100); CHECK(cq_enqueue(q, &b) == CQ_OK);
    b = make_ban("2.2.2.2", 5, 105); CHECK(cq_enqueue(q, &b) == CQ_OK);
    b = make_ban("3.3.3.3", 9, 109); CHECK(cq_enqueue(q, &b) == CQ_OK);
    CHECK(cq_is_full(q) && cq_size(q) == 3);
    b = make_ban("4.4.4.4", 9, 200); CHECK(cq_enqueue(q, &b) == CQ_FULL);
    CHECK(cq_peek(q, &out) && strcmp(out.ip, "1.1.1.1") == 0);
    CHECK(cq_peek_rear(q, &out) && strcmp(out.ip, "3.3.3.3") == 0);
    CHECK(cq_dequeue(q, &out) && strcmp(out.ip, "1.1.1.1") == 0);
    CHECK(cq_size(q) == 2 && !cq_is_full(q));
    cq_destroy(q);
}

static void test_wraparound(void) {
    printf("wrap-around reuses freed slots\n");
    CircularQueue *q = cq_create(3);
    BanEntry b, out;
    char ip[32];
    long long t = 0;
    for (int round = 0; round < 10; round++) {     /* 10 laps of a 3-slot ring */
        snprintf(ip, sizeof ip, "10.0.0.%d", round);
        b = make_ban(ip, t, t + 50); t += 1;
        CHECK(cq_enqueue(q, &b) == CQ_OK);
        if (cq_size(q) == 3) {
            CHECK(cq_dequeue(q, &out));
        }
    }
    CHECK(q->front >= 0 && q->front < 3 && q->rear >= 0 && q->rear < 3);
    CHECK(cq_get(q, 0) != NULL && strcmp(cq_get(q, 0)->ip, "10.0.0.8") == 0);
    CHECK(cq_get(q, 1) != NULL && strcmp(cq_get(q, 1)->ip, "10.0.0.9") == 0);
    CHECK(cq_get(q, 2) == NULL && cq_get(q, -1) == NULL);
    cq_destroy(q);
}

static void test_order_rule(void) {
    printf("out-of-order expiry is refused\n");
    CircularQueue *q = cq_create(4);
    BanEntry b = make_ban("1.1.1.1", 0, 300);
    CHECK(cq_enqueue(q, &b) == CQ_OK);
    b = make_ban("2.2.2.2", 10, 70);                /* ends earlier: refused */
    CHECK(cq_enqueue(q, &b) == CQ_OUT_OF_ORDER);
    b = make_ban("2.2.2.2", 10, 300);               /* equal expiry is fine  */
    CHECK(cq_enqueue(q, &b) == CQ_OK);
    b = make_ban("3.3.3.3", 50, 40);                /* ends before it starts */
    CHECK(cq_enqueue(q, &b) == CQ_BAD_INPUT);
    CHECK(cq_enqueue(NULL, &b) == CQ_BAD_INPUT);
    CHECK(cq_size(q) == 2);
    cq_destroy(q);
}

static void test_expire_and_unblock(void) {
    printf("expiry, manual unblock (lazy deletion)\n");
    CircularQueue *q = cq_create(8);
    BanEntry b, expired[8];
    b = make_ban("1.1.1.1", 0, 100);  cq_enqueue(q, &b);
    b = make_ban("2.2.2.2", 10, 110); cq_enqueue(q, &b);
    b = make_ban("3.3.3.3", 20, 120); cq_enqueue(q, &b);
    CHECK(cq_active_count(q) == 3);
    CHECK(cq_deactivate(q, "2.2.2.2") == 1);
    CHECK(cq_deactivate(q, "2.2.2.2") == 0);        /* already inactive */
    CHECK(cq_deactivate(q, "9.9.9.9") == 0);        /* not in queue     */
    CHECK(cq_active_count(q) == 2 && cq_size(q) == 3);

    CHECK(cq_expire(q, 99, expired, 8) == 0);       /* nothing ended yet */
    CHECK(cq_expire(q, 100, expired, 8) == 1);      /* boundary: <= now  */
    CHECK(strcmp(expired[0].ip, "1.1.1.1") == 0);
    /* at 115 the inactive 2.2.2.2 leaves the queue but is NOT reported */
    CHECK(cq_expire(q, 115, expired, 8) == 0);
    CHECK(cq_size(q) == 1);
    CHECK(cq_expire(q, 1000, expired, 8) == 1 && strcmp(expired[0].ip, "3.3.3.3") == 0);
    CHECK(cq_is_empty(q));

    /* re-ban after unblock: only the new entry is active */
    b = make_ban("5.5.5.5", 0, 50);  cq_enqueue(q, &b);
    cq_deactivate(q, "5.5.5.5");
    b = make_ban("5.5.5.5", 10, 60); cq_enqueue(q, &b);
    CHECK(cq_active_count(q) == 1);
    CHECK(cq_expire(q, 55, NULL, 0) == 0);          /* old inactive one dropped */
    CHECK(cq_expire(q, 60, NULL, 0) == 1);
    cq_destroy(q);
}

/* Random stress test against a simple, obviously-correct array model. */
static void test_random_vs_model(void) {
    printf("random stress (20000 operations vs naive array)\n");
    enum { CAP = 16, OPS = 20000 };
    CircularQueue *q = cq_create(CAP);
    long long model[CAP];
    int model_size = 0;
    long long next_expiry = 0;
    srand(12345);
    for (int op = 0; op < OPS; op++) {
        int r = rand() % 3;
        if (r < 2) {                                 /* enqueue */
            next_expiry += rand() % 3;               /* never decreasing */
            BanEntry b = make_ban("x", 0, next_expiry);
            int result = cq_enqueue(q, &b);
            if (model_size == CAP) CHECK(result == CQ_FULL);
            else { CHECK(result == CQ_OK); model[model_size++] = next_expiry; }
        } else {                                     /* dequeue */
            BanEntry out;
            int ok = cq_dequeue(q, &out);
            if (model_size == 0) CHECK(!ok);
            else {
                CHECK(ok && out.expires_at == model[0]);
                for (int i = 1; i < model_size; i++) model[i - 1] = model[i];
                model_size--;
            }
        }
        if (cq_size(q) != model_size) { CHECK(0); break; }
    }
    cq_clear(q);
    CHECK(cq_is_empty(q));
    cq_destroy(q);
}

static void test_expire_batches(void) {
    printf("cq_expire hands back results in batches\n");
    CircularQueue *q = cq_create(64);
    BanEntry b, out[4];
    char ip[32];
    for (int i = 0; i < 10; i++) {
        snprintf(ip, sizeof ip, "10.0.0.%d", i);
        b = make_ban(ip, 0, 100 + i);
        cq_enqueue(q, &b);
    }
    cq_deactivate(q, "10.0.0.1");
    int total = 0, calls = 0, got;
    do { got = cq_expire(q, 1000, out, 4); total += got; calls++; } while (got == 4);
    CHECK(total == 9 && calls == 3 && cq_is_empty(q));
    cq_destroy(q);
}

int main(void) {
    test_basic();
    test_expire_batches();
    test_wraparound();
    test_order_rule();
    test_expire_and_unblock();
    test_random_vs_model();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
