# Data structures: explanation and viva preparation

Every data structure in this project is written by hand in C11 (no libraries). For each one:
purpose, how it is laid out in memory, why it was chosen, every function, complexity, a small
example, and questions an examiner is likely to ask (with answers).

Notation: n = number of stored items. "Amortized O(1)" = an operation is usually O(1); now and then
it costs O(n), but averaged over many operations it is still O(1) each.

## Summary table

| Structure | File | Used for | Key operations and cost |
|---|---|---|---|
| Deque (circular array) | `deque.c` | 3 time windows per IP | push rear O(1) amortized, pop front O(1), peek O(1) |
| Hash table (chaining) | `hashtable.c` | IP records, username stats, sets, heap index | put / get / remove O(1) average, O(n) worst |
| Max heap + index map | `heap.c` | ranking IPs by threat score | set (insert or update) O(log n), peek O(1), top-k O(n + k log n) |
| Circular queue | `circular_queue.c` | simulated bans, in expiry order | enqueue / dequeue / peek O(1), unblock O(n) |
| Singly linked list | `linkedlist.c` | recent alerts, newest first | add at head O(1) (+ trim O(cap)), get(i) O(i) |
| Stack (bonus) | `stack.c` | Undo on the Settings page | push / pop / peek O(1) |
| Dynamic array | `parser.c` (`EventList`) | loaded or simulated events | append amortized O(1), index O(1) |
| Merge sort | `simulator.c` | sorting events by time | O(n log n) time, O(n) extra space, stable |

Linked lists also appear inside the hash table (each bucket is a chain), and `app.c` uses two small
fixed-size ring buffers (the last 400 events for the Live page, and 60 one-minute buckets for the chart).

---

## 1. Deque on a circular array (`deque.c`, `deque.h`)

**Purpose.** One deque holds the timestamps of one IP's failed logins for one window. Every IP has
three: 10 s, 10 min, 1 h. New failures go in at the **rear**; timestamps that are too old leave from
the **front**.

**Layout.**
```c
typedef struct {
    long long *data;   /* array allocated with malloc            */
    int capacity;      /* number of slots                        */
    int front;         /* index of the oldest element            */
    int size;          /* number of elements stored              */
} Deque;
```
Logical position i (0 = oldest) is stored at `data[(front + i) % capacity]`. The rear (next free
slot) is `(front + size) % capacity`. When an index runs past the end it wraps around to 0.

**Why a circular array?** With a normal array, removing from the front means shifting every element
left: O(n). In a ring we just move `front` forward: O(1). A linked list would also be O(1), but needs
a malloc per timestamp and has poor cache locality; the array uses one block of memory.

**Functions.**

| Function | What it does | Cost |
|---|---|---|
| `deque_create(cap)` | malloc the struct and the array; front = size = 0 | O(1) |
| `deque_destroy(dq)` | free the array, then the struct | O(1) |
| `deque_push_rear(dq, t)` | if full, `deque_expand` doubles the array; write at the rear index; size++ | O(1) amortized |
| `deque_pop_front(dq, &t)` | read `data[front]`; `front = (front + 1) % capacity`; size-- | O(1) |
| `deque_peek_front / peek_rear` | read without removing | O(1) |
| `deque_is_empty / is_full / size` | compare size with 0 / capacity | O(1) |
| `deque_remove_older_than(dq, cutoff)` | pop from the front while the oldest timestamp < cutoff | O(k), k = removed |
| `deque_expand` (static) | new array of 2 x capacity; copy elements in logical order so front becomes 0 | O(n), rare |

**Why push is O(1) amortized.** Doubling happens at sizes 1, 2, 4, 8, ... n. The total copying is
1 + 2 + 4 + ... + n < 2n, so over n pushes the copying cost is less than 2 per push.

**Why `remove_older_than` can stop early.** Timestamps arrive in time order, so the front is always
the oldest. As soon as the front is inside the window, everything behind it is too.

**Space.** O(capacity). The array never shrinks, so capacity is at most twice the largest size ever reached.

**Example.** capacity 4: push 1, 2, 3 -> pop, pop (front = 2) -> push 4, 5, 6. Now the array is
`[5, 6, 3, 4]` with front = 2: logical order 3, 4, 5, 6. It is full without having grown. This exact
case is `test_wraparound` in `tests/test_deque.c`.

**Viva questions**
* *Why keep `size` instead of computing it from front and rear?* When front == rear the ring is
  either empty or full; `size` tells which.
* *What happens when it is full?* `deque_push_rear` doubles the array (copying in logical order) and continues.
* *Why a deque and not a queue, if we only push at the rear and pop at the front?* The window
  operations only need a queue, but the deque also offers `peek_rear` (the newest failure), and the
  assignment specified a deque. The circular array is the same in both cases.
* *How is the memory freed?* `deque_destroy` frees `data` and then the struct. `free_ip_record` in
  `detector.c` calls it for all three deques of an IP.
* *What if malloc fails?* `deque_create` returns NULL (and frees the half-built struct);
  `deque_push_rear` returns 0 and the deque stays unchanged.

---

## 2. Hash table with separate chaining (`hashtable.c`, `hashtable.h`)

**Purpose.** Find a record by a text key in O(1) on average. Used for: IP -> IpRecord, username ->
UserStats, per-IP set of failed usernames (username -> count), per-username set of failing IPs
(IP -> last failure time), the heap's index map, and the evaluator's "already counted" set.

**Layout.**
```c
typedef struct HashNode { char key[64]; void *value; struct HashNode *next; } HashNode;
typedef struct { HashNode **buckets; int bucket_count; int count; } HashTable;
```
`buckets` is an array of linked-list heads. The value is a `void *`, so the same table code stores
any type; the caller decides what it points to.

**Hash function: djb2.** `hash = 5381; for each character c: hash = hash * 33 + c`. The bucket is
`hash % bucket_count`. It is short, fast and spreads typical text keys well.

**Collisions: separate chaining.** Two keys in the same bucket are both kept in that bucket's
linked list. A new node is inserted at the head (O(1)).

**Resizing.** When `count > 0.75 x bucket_count` (load factor 75 %), the bucket array doubles and
every node is moved to its new bucket. Nodes are re-linked, not copied, so no node memory is allocated.

**Functions.**

| Function | What it does | Cost |
|---|---|---|
| `ht_create(n)` | malloc the struct; calloc the bucket array (all NULL = empty lists) | O(n) |
| `ht_put(t, key, value)` | if the key exists, replace its value; else malloc a node, insert at head, maybe resize | O(1) average |
| `ht_get(t, key)` | hash, walk one chain comparing with strcmp | O(1) average |
| `ht_contains` | same as get, returns 0/1 | O(1) average |
| `ht_remove(t, key, &old)` | unlink the node (head case or bypass case), free it, hand back the value | O(1) average |
| `ht_for_each(t, fn, ctx)` | call fn for every entry (must not add or remove inside) | O(buckets + n) |
| `ht_destroy(t, free_fn)` | free every node (and value, if free_fn given), then the arrays | O(buckets + n) |
| `resize` (static) | double buckets, relink all nodes | O(n), rare: amortized O(1) per put |

**Worst case O(n):** if every key landed in one bucket, a lookup would walk the whole chain. The
load-factor rule and a decent hash keep chains short in practice (the test inserts 5000 keys and
checks every one).

**Space.** O(bucket_count + n); bucket_count is at most about 2.7 x n after resizing.

**Example.** Keys "10.0.0.1" and "10.0.0.9" may land in the same bucket: the bucket's list is then
`"10.0.0.9" -> "10.0.0.1" -> NULL` (newest at the head). `ht_get("10.0.0.1")` walks two nodes.

**Viva questions**
* *Why separate chaining instead of open addressing?* Deletion is simple (unlink a node; no
  "tombstones"), and the table never "fills up".
* *Why 0.75?* A common balance: lower wastes memory, higher makes chains longer.
* *Why does `ht_remove` need the previous node?* To bypass the removed node: `previous->next = node->next`.
  If the removed node is the head, the bucket pointer itself is updated.
* *Why can't we remove inside `ht_for_each`?* Removing frees the node the loop is standing on. The
  detector collects keys first and removes them afterwards (`prune_user` in `detector.c`).
* *Who frees the values?* The caller: `ht_destroy(table, free_ip_record)` frees each IpRecord;
  `ht_remove` returns the value so the caller can free it.

---

## 3. Max heap with an index map (`heap.c`, `heap.h`)

**Purpose.** Rank IPs by threat score: the most dangerous IP is always at the top, and the
dashboard shows the top 10.

**Layout.** A complete binary tree stored in an array:
```c
typedef struct { char key[64]; double priority; } HeapItem;
typedef struct { HeapItem *items; int size; int capacity; HashTable *index_of; } MaxHeap;
```
For index i: parent = (i - 1) / 2, children = 2i + 1 and 2i + 2. **Heap rule:** every parent's
priority >= its children's, so `items[0]` is the maximum.

**The index map.** Scores change all the time, and to update an IP we must find it inside the heap.
Searching the array would be O(n). Instead `index_of` (a hash table) maps IP -> its array position.
Every swap updates the map (`swap_items`). Finding an item is then O(1), and moving it O(log n).

**Functions.**

| Function | What it does | Cost |
|---|---|---|
| `heap_set(h, key, p)` | key new: append at the end, sift up. Key exists: change priority, sift up or down | O(log n) |
| `heap_peek_max` | read items[0] | O(1) |
| `heap_extract_max` | take items[0], move the last item to the root, sift down | O(log n) |
| `heap_remove(h, key)` | find via the map, replace with the last item, sift up or down | O(log n) |
| `heap_get_priority`, `heap_contains` | map lookup | O(1) average |
| `heap_top_k(h, k, out)` | copy the array, extract k times from the copy (real heap untouched) | O(n + k log n) |
| `heap_check_invariants` | test helper: heap rule holds and map agrees with array | O(n) |
| `sift_up` / `sift_down` (static) | swap with parent / larger child until the rule holds | O(log n) |

**Why O(log n)?** A complete binary tree with n nodes has height floor(log2 n); sifting moves one
level per swap.

**Space.** O(n) for the array plus O(n) for the map.

**Example.** Scores 71 (A), 58 (B), 67 (C): array `[A71, B58, C67]`. B rises to 80: B is at index 1,
parent 0 has 71 < 80, swap: `[B80, A71, C67]`, map updated to B->0, A->1.

**How the detector uses it.** After every score change, `store_score` calls `heap_set`. An IP whose
score drops to 0 is removed with `heap_remove`, so the heap only holds currently interesting IPs.

**Viva questions**
* *Why not keep a sorted array?* An update would cost O(n) to move the item. The heap does O(log n).
* *Why not a balanced BST?* It would also work, but a heap is simpler and we only need the maximum
  and the top 10, not a full sorted order.
* *What breaks if you forget to update the index map in a swap?* The next update would move the
  wrong item. `heap_check_invariants` and a 20,000-operation random test catch exactly this.
* *Why does `heap_top_k` copy the array?* Extracting from the real heap would destroy the ranking
  that the detector keeps updating.

---

## 4. Circular queue of bans (`circular_queue.c`, `circular_queue.h`)

**Purpose.** Hold the active simulated bans in the order they end, so expiring them is cheap.

**Layout.** A fixed array (capacity 4096 in the detector) used as a ring:
```c
typedef struct { char ip[64]; char reason[48]; double score;
                 long long blocked_at, expires_at; int active; } BanEntry;
typedef struct { BanEntry *items; int capacity; int front; int rear; int size; } CircularQueue;
```
`front` = oldest entry, `rear` = where the next entry goes. Both move with `(x + 1) % capacity`.

**Why FIFO works here.** Every ban lasts the same `ban_duration`, so bans that start earlier also
end earlier: the queue is automatically sorted by expiry. Expiring = "while the front has expired,
dequeue". `cq_enqueue` enforces this by **refusing** an entry that ends before the rear entry
(`CQ_OUT_OF_ORDER`). How the detector handles a shortened duration is described in DETECTION.md section 7.

**Manual unblock: lazy deletion.** Removing from the middle of a queue is not a queue operation.
`cq_deactivate` finds the entry (O(n)) and sets `active = 0`; when it reaches the front it is
dropped silently.

**Functions.**

| Function | What it does | Cost |
|---|---|---|
| `cq_create(cap)` / `cq_destroy` / `cq_clear` | allocate / free / reset front, rear, size | O(1) |
| `cq_enqueue(q, &entry)` | refuse if full, invalid or out of order; copy to `items[rear]`; rear moves | O(1) |
| `cq_dequeue(q, &out)` | copy `items[front]`; front moves; size-- | O(1) |
| `cq_peek` / `cq_peek_rear` | read front / last entry (`(rear - 1 + cap) % cap`) | O(1) |
| `cq_is_empty` / `cq_is_full` / `cq_size` | compare size | O(1) |
| `cq_get(q, i)` | i-th entry from the front, for the dashboard list | O(1) |
| `cq_deactivate(q, ip)` | mark the active entry for ip inactive | O(n) |
| `cq_expire(q, now, out, max)` | dequeue expired entries, report active ones in batches | O(expired) |
| `cq_active_count(q)` | count active entries | O(n) |

**Space.** O(capacity), fixed. Memory never grows, which is one reason a circular queue was chosen.

**Example.** Ban duration 300 s. Bans at t = 0, 10, 20 end at 300, 310, 320. At t = 305,
`cq_expire` dequeues only the first. If the second was unblocked by hand, at t = 315 it is dequeued
but not reported.

**Viva questions**
* *Full and empty both have front == rear; how do you tell them apart?* With the `size` field.
* *Why not a heap ordered by expiry time?* It would allow different durations, but every operation
  would be O(log n). With one duration, the circular queue gives O(1) and is simpler.
* *What if the ban duration is changed?* New bans use it. If it got shorter, the new ban is extended
  to end with the newest older ban, so the queue stays sorted; it is never shortened.
* *Why is unblock O(n)?* We must find the IP; the queue has no index. Unblock is rare (a button
  click), so this is acceptable. A hash table IP -> slot could make it O(1).

---

## 5. Singly linked list of alerts (`linkedlist.c`, `linkedlist.h`)

**Purpose.** The "Recent alerts" panel: newest alert first, at most 200 kept.

**Layout.**
```c
typedef struct AlertNode { int id; long long time; char ip[64]; char username[64];
                           char category[32]; char severity[16]; double score;
                           char message[160]; struct AlertNode *next; } AlertNode;
typedef struct { AlertNode *head; int size; int max_size; int next_id; } AlertList;
```

**Why a linked list?** A new alert is inserted at the head in O(1), and walking from the head
already gives newest -> oldest, which is the display order.

**Functions.**

| Function | What it does | Cost |
|---|---|---|
| `alert_list_create(max)` | malloc the list header | O(1) |
| `alert_list_add(list, &alert)` | malloc a node, copy, give it the next id, link at head; if over the cap, remove the tail | O(1) + O(max) when trimming |
| `remove_tail` (static) | walk to the node before the tail, free the tail | O(n) |
| `alert_list_get(list, i)` | follow `next` i times | O(i) |
| `alert_list_find(list, id)` | linear search | O(n) |
| `alert_list_clear` / `destroy` | free every node (saving `next` before each free) | O(n) |

**Space.** O(max_size) = at most 200 nodes.

**Viva questions**
* *Why is trimming O(n)?* A singly linked list has no back pointers, so finding the node before
  the tail means walking. A doubly linked list with a tail pointer would make it O(1); with
  n <= 200 the simple version is fine.
* *Why save `next` before `free(node)`?* After `free`, reading `node->next` is undefined behaviour.
* *Where else are linked lists used?* Every hash-table bucket is a singly linked list.

---

## 6. Stack (bonus) (`stack.c`, `stack.h`)

**Purpose.** "Undo last change" on the Settings page. Before new settings are applied, the old
ones are pushed; Undo pops the most recent. Last In, First Out is exactly undo order.

**Layout.** `Settings items[20]; int top;` - the array lives inside the struct, so there is no
malloc at all. `items[top - 1]` is the top.

| Function | Cost |
|---|---|
| `stack_push` | O(1); when full, the bottom (oldest) item is dropped by shifting 19 items down: O(capacity) |
| `stack_pop` / `stack_peek` | O(1) |
| `stack_is_empty` / `is_full` / `size` | O(1) |

**Viva question.** *Why drop the oldest when full instead of refusing?* For undo, the most recent
changes matter; refusing would make the newest change impossible to undo.

---

## 7. Dynamic array of events (`EventList` in `parser.c`)

Holds every loaded or simulated `LoginEvent`. `event_list_add` doubles the capacity with `realloc`
when full (amortized O(1), same argument as the deque). Indexing is O(1).

**A bug the tests found.** The first version read the new event *after* `realloc`. If the caller
passed a pointer to an event already inside the list, `realloc` could move the array and the
pointer would point to freed memory. AddressSanitizer caught it; the fix copies the event first.
The HTTP server had the same class of bug: it kept a *pointer* to the end of the request headers
while the buffer could still be reallocated. It now keeps an *offset* (a number), which stays
valid wherever the buffer moves. Both are good examples for "what can go wrong with realloc".

## 8. Merge sort (`simulator.c`)

The simulator generates attack events and background events separately, then sorts them by time
with a bottom-up merge sort: merge runs of width 1, 2, 4, ... using a temporary array. Each event
moves together with its ground-truth label. O(n log n) time, O(n) extra space. It is **stable**
(`<=` in `merge`), so events with the same timestamp keep their original order, which makes runs
repeatable.

## 9. Random numbers (`simulator.c`)

`rand()` gives different sequences on Windows and Linux, which would make "seed 2026" mean
different things on different machines. The simulator uses xorshift64*: three shift/XOR steps and a
multiplication on a 64-bit integer. The same seed gives the same events on every computer.

---

## General viva questions

* **Time complexity of processing one event?** O(1) average for the hash lookups, O(1) amortized
  for the deque pushes, O(k) to drop k expired timestamps (each timestamp is removed once, so this is
  amortized O(1)), and O(log n) for the heap update. Overall **O(log n)** per event, n = IPs in the ranking.
* **Total memory?** O(I + F + U): I = distinct IPs (records), F = failures inside the 1 h windows,
  U = username table entries. Bans and alerts are capped (4096 and 200).
* **Why not just one window?** See the evaluation: a single window misses low-and-slow, credential
  stuffing and distributed attacks completely.
* **How do you know there are no memory leaks?** All 12 test programs and the server (under a stress
  test with fuzzed requests) were run with AddressSanitizer and LeakSanitizer: no errors, no leaks.
* **Why C and not Python?** The assignment asks for hand-written data structures; C makes every
  allocation, pointer and array index explicit, so nothing is hidden by a library.
