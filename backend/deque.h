/*
 * deque.h - Double-ended queue built on a CIRCULAR ARRAY.
 *
 * Purpose : keep the timestamps of failed logins for ONE time window
 *           (10 s, 10 min or 1 h) of ONE IP address.
 * Why     : new events arrive at the rear, old events expire at the front.
 *           A circular array makes both operations O(1) without shifting.
 *
 * Timestamps are stored as long long (seconds since 1970).
 */
#ifndef DEQUE_H
#define DEQUE_H

typedef struct {
    long long *data;   /* heap array holding the timestamps            */
    int capacity;      /* how many slots the array has                 */
    int front;         /* index of the OLDEST element                  */
    int size;          /* how many elements are stored right now       */
} Deque;

/* Create / destroy. create returns NULL on failure. */
Deque *deque_create(int initial_capacity);
void   deque_destroy(Deque *dq);

/* Status */
int deque_is_empty(const Deque *dq);
int deque_is_full(const Deque *dq);
int deque_size(const Deque *dq);

/* Operations. Return 1 on success, 0 on failure. */
int deque_push_rear(Deque *dq, long long timestamp);  /* grows if full */
int deque_pop_front(Deque *dq, long long *out);
int deque_peek_front(const Deque *dq, long long *out);
int deque_peek_rear(const Deque *dq, long long *out);

/* Sliding-window helper: removes every timestamp < cutoff from the front.
 * Returns how many were removed. */
int deque_remove_older_than(Deque *dq, long long cutoff);

#endif
