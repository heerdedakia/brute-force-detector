/*
 * circular_queue.c - fixed-size circular queue of bans (see circular_queue.h).
 *
 * Ring idea: front and rear move forward with "+1 then % capacity", so when
 * they reach the end of the array they wrap around to index 0. Slots freed
 * at the front are reused by the rear. No element is ever shifted.
 *
 * Full vs empty: both have front == rear, so we keep an explicit size.
 *
 * Memory: one malloc for the struct, one for the array, both freed in
 * cq_destroy. The capacity is FIXED (that is what makes it a circular queue,
 * and it caps memory use). When full, cq_enqueue refuses the new entry.
 */
#include <stdlib.h>
#include <string.h>
#include "circular_queue.h"

CircularQueue *cq_create(int capacity) {
    if (capacity < 1) capacity = 1;

    CircularQueue *q = (CircularQueue *)malloc(sizeof(CircularQueue));
    if (q == NULL) return NULL;

    q->items = (BanEntry *)malloc(sizeof(BanEntry) * (size_t)capacity);
    if (q->items == NULL) {
        free(q);
        return NULL;
    }
    q->capacity = capacity;
    cq_clear(q);
    return q;
}

void cq_destroy(CircularQueue *q) {
    if (q == NULL) return;
    free(q->items);
    free(q);
}

void cq_clear(CircularQueue *q) {
    if (q == NULL) return;
    q->front = 0;
    q->rear = 0;
    q->size = 0;
}

int cq_is_empty(const CircularQueue *q) { return q == NULL || q->size == 0; }
int cq_is_full(const CircularQueue *q)  { return q != NULL && q->size == q->capacity; }
int cq_size(const CircularQueue *q)     { return q == NULL ? 0 : q->size; }

int cq_enqueue(CircularQueue *q, const BanEntry *entry) {
    if (q == NULL || entry == NULL || entry->expires_at < entry->blocked_at)
        return CQ_BAD_INPUT;
    if (cq_is_full(q)) return CQ_FULL;

    /* Keep the queue sorted by expiry time (see the header comment). */
    BanEntry last;
    if (cq_peek_rear(q, &last) && entry->expires_at < last.expires_at)
        return CQ_OUT_OF_ORDER;

    q->items[q->rear] = *entry;                 /* struct copy */
    q->items[q->rear].ip[CQ_IP_MAX - 1] = '\0';
    q->items[q->rear].reason[CQ_REASON_MAX - 1] = '\0';
    q->rear = (q->rear + 1) % q->capacity;      /* wrap-around */
    q->size++;
    return CQ_OK;
}

int cq_dequeue(CircularQueue *q, BanEntry *out) {
    if (cq_is_empty(q)) return 0;
    if (out != NULL) *out = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;    /* wrap-around */
    q->size--;
    return 1;
}

int cq_peek(const CircularQueue *q, BanEntry *out) {
    if (cq_is_empty(q) || out == NULL) return 0;
    *out = q->items[q->front];
    return 1;
}

int cq_peek_rear(const CircularQueue *q, BanEntry *out) {
    if (cq_is_empty(q) || out == NULL) return 0;
    /* rear points one PAST the last entry; step back one, wrapping safely */
    int last = (q->rear - 1 + q->capacity) % q->capacity;
    *out = q->items[last];
    return 1;
}

const BanEntry *cq_get(const CircularQueue *q, int i) {
    if (q == NULL || i < 0 || i >= q->size) return NULL;
    return &q->items[(q->front + i) % q->capacity];
}

int cq_deactivate(CircularQueue *q, const char *ip) {
    if (q == NULL || ip == NULL) return 0;
    for (int i = 0; i < q->size; i++) {
        BanEntry *entry = &q->items[(q->front + i) % q->capacity];
        if (entry->active && strcmp(entry->ip, ip) == 0) {
            entry->active = 0;                  /* lazy deletion */
            return 1;
        }
    }
    return 0;
}

int cq_expire(CircularQueue *q, long long now, BanEntry *expired_out, int max_out) {
    int expired_active = 0;
    BanEntry front;
    /* Sorted by expiry, so we stop at the first ban that is still running.
     * With an output buffer we also stop when the buffer is full; the
     * caller simply calls again for the rest. */
    while (cq_peek(q, &front) && front.expires_at <= now) {
        if (expired_out != NULL && front.active && expired_active >= max_out) break;
        cq_dequeue(q, NULL);
        if (!front.active) continue;            /* manually unblocked earlier */
        if (expired_out != NULL) expired_out[expired_active] = front;
        expired_active++;
    }
    return expired_active;
}

int cq_active_count(const CircularQueue *q) {
    int count = 0;
    for (int i = 0; q != NULL && i < q->size; i++)
        if (cq_get(q, i)->active) count++;
    return count;
}
