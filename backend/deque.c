/*
 * deque.c - circular-array deque (see deque.h for the big picture).
 *
 * Circular idea: the array is treated as a ring. Logical position i
 * (0 = oldest) lives at array index (front + i) % capacity.
 * When we run off the end of the array we wrap around to index 0.
 *
 * Memory: one malloc for the struct, one for the array.
 *         deque_destroy frees both. Growing uses a new array + free(old).
 */
#include <stdlib.h>
#include "deque.h"

Deque *deque_create(int initial_capacity) {
    if (initial_capacity < 1) initial_capacity = 1;

    Deque *dq = (Deque *)malloc(sizeof(Deque));
    if (dq == NULL) return NULL;

    dq->data = (long long *)malloc(sizeof(long long) * (size_t)initial_capacity);
    if (dq->data == NULL) {          /* second malloc failed: undo the first */
        free(dq);
        return NULL;
    }
    dq->capacity = initial_capacity;
    dq->front = 0;
    dq->size = 0;
    return dq;
}

void deque_destroy(Deque *dq) {
    if (dq == NULL) return;
    free(dq->data);
    free(dq);
}

int deque_is_empty(const Deque *dq) { return dq == NULL || dq->size == 0; }
int deque_is_full(const Deque *dq)  { return dq != NULL && dq->size == dq->capacity; }
int deque_size(const Deque *dq)     { return dq == NULL ? 0 : dq->size; }

/*
 * Double the capacity. Elements are copied in logical order
 * (oldest first) so that front becomes 0 in the new array.
 * Cost O(n), but it happens rarely (capacity doubles each time),
 * so push_rear is O(1) AMORTIZED.
 */
static int deque_expand(Deque *dq) {
    int new_capacity = dq->capacity * 2;
    long long *new_data = (long long *)malloc(sizeof(long long) * (size_t)new_capacity);
    if (new_data == NULL) return 0;

    for (int i = 0; i < dq->size; i++) {
        new_data[i] = dq->data[(dq->front + i) % dq->capacity];
    }
    free(dq->data);
    dq->data = new_data;
    dq->capacity = new_capacity;
    dq->front = 0;
    return 1;
}

int deque_push_rear(Deque *dq, long long timestamp) {
    if (dq == NULL) return 0;
    if (deque_is_full(dq) && !deque_expand(dq)) return 0;

    int rear_index = (dq->front + dq->size) % dq->capacity;  /* first free slot */
    dq->data[rear_index] = timestamp;
    dq->size++;
    return 1;
}

int deque_pop_front(Deque *dq, long long *out) {
    if (deque_is_empty(dq)) return 0;
    if (out != NULL) *out = dq->data[dq->front];
    dq->front = (dq->front + 1) % dq->capacity;   /* wrap-around */
    dq->size--;
    return 1;
}

int deque_peek_front(const Deque *dq, long long *out) {
    if (deque_is_empty(dq) || out == NULL) return 0;
    *out = dq->data[dq->front];
    return 1;
}

int deque_peek_rear(const Deque *dq, long long *out) {
    if (deque_is_empty(dq) || out == NULL) return 0;
    *out = dq->data[(dq->front + dq->size - 1) % dq->capacity];
    return 1;
}

int deque_remove_older_than(Deque *dq, long long cutoff) {
    int removed = 0;
    long long oldest;
    /* timestamps arrive in time order, so the oldest is always at the front:
     * we can stop at the first one that is still inside the window. */
    while (deque_peek_front(dq, &oldest) && oldest < cutoff) {
        deque_pop_front(dq, NULL);
        removed++;
    }
    return removed;
}
