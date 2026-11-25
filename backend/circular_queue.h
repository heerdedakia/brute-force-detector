/*
 * circular_queue.h - FIXED-SIZE CIRCULAR QUEUE of simulated IP bans.
 *
 * Purpose : remember which IPs are banned and when each ban ends.
 * Why FIFO: every ban lasts the same time (one ban_duration from Settings),
 *           so the ban that started first also ENDS first. Expiring bans is
 *           then just "look at the front, dequeue while it has expired":
 *           O(1) per expired ban, no searching, no sorting.
 *
 * Safety rule (enforced by cq_enqueue): expires_at must never be smaller than
 * the expires_at of the entry at the rear. This keeps the queue sorted by
 * expiry time, which is what makes FIFO expiry correct.
 *
 * Manual unblock: we cannot remove from the middle of a queue cheaply, so the
 * entry is only marked inactive (active = 0). It is skipped when it reaches
 * the front ("lazy deletion").
 */
#ifndef CIRCULAR_QUEUE_H
#define CIRCULAR_QUEUE_H

#define CQ_IP_MAX     64
#define CQ_REASON_MAX 48

typedef struct {
    char ip[CQ_IP_MAX];
    char reason[CQ_REASON_MAX];   /* e.g. "Fast brute-force"              */
    double score;                 /* threat score when the ban started     */
    long long blocked_at;         /* simulation time (epoch seconds)       */
    long long expires_at;         /* simulation time when the ban ends     */
    int active;                   /* 1 = banned, 0 = manually unblocked    */
} BanEntry;

typedef struct {
    BanEntry *items;      /* array used as a ring                          */
    int capacity;         /* fixed number of slots                         */
    int front;            /* index of the oldest entry                     */
    int rear;             /* index where the NEXT entry will be written    */
    int size;             /* number of entries currently stored            */
} CircularQueue;

/* Result codes of cq_enqueue */
#define CQ_OK            1
#define CQ_FULL          0
#define CQ_OUT_OF_ORDER -1
#define CQ_BAD_INPUT    -2

CircularQueue *cq_create(int capacity);
void cq_destroy(CircularQueue *q);
void cq_clear(CircularQueue *q);

int cq_is_empty(const CircularQueue *q);
int cq_is_full(const CircularQueue *q);
int cq_size(const CircularQueue *q);          /* includes inactive entries */

/* Adds at the rear. Returns CQ_OK, CQ_FULL, CQ_OUT_OF_ORDER or CQ_BAD_INPUT. */
int cq_enqueue(CircularQueue *q, const BanEntry *entry);
int cq_dequeue(CircularQueue *q, BanEntry *out);          /* 1 ok, 0 empty */
int cq_peek(const CircularQueue *q, BanEntry *out);       /* 1 ok, 0 empty */
int cq_peek_rear(const CircularQueue *q, BanEntry *out);  /* 1 ok, 0 empty */

/* Logical access for display: i = 0 is the front (oldest). Returns NULL if
 * i is out of range. */
const BanEntry *cq_get(const CircularQueue *q, int i);

/* Marks the ACTIVE entry for ip as inactive. O(n) scan.
 * Returns 1 if an active entry was found, 0 otherwise. */
int cq_deactivate(CircularQueue *q, const char *ip);

/* Removes entries whose expires_at <= now from the front.
 * Inactive (manually unblocked) entries are dropped silently.
 * If expired_out is NULL: removes ALL expired entries, max_out is ignored.
 * Otherwise: copies each expired ACTIVE entry into expired_out and stops
 * after max_out of them (call again until it returns less than max_out).
 * Returns the number of ACTIVE entries that expired in this call. */
int cq_expire(CircularQueue *q, long long now, BanEntry *expired_out, int max_out);

int cq_active_count(const CircularQueue *q);

#endif
