/*
 * heap.h - MAX HEAP used as a priority queue of IP threat scores.
 *
 * Purpose : always know which IP has the highest threat score, and list the
 *           top-K dangerous IPs.
 * Idea    : the heap is a complete binary tree stored in an array.
 *           parent of i = (i-1)/2, children = 2i+1 and 2i+2.
 *           Every parent has a priority >= its children, so items[0] is the max.
 *
 * Score UPDATES: when an IP's score changes we must find it inside the heap.
 * A hash table (key -> array index) gives that in O(1); after the change we
 * move the item up or down in O(log n).
 */
#ifndef HEAP_H
#define HEAP_H

#include "hashtable.h"

#define HEAP_KEY_MAX HT_KEY_MAX

typedef struct {
    char key[HEAP_KEY_MAX];     /* IP address text */
    double priority;            /* threat score    */
} HeapItem;

typedef struct {
    HeapItem *items;            /* the tree stored as an array              */
    int size;
    int capacity;
    HashTable *index_of;        /* key -> pointer to int (position in items) */
} MaxHeap;

MaxHeap *heap_create(int initial_capacity);
void     heap_destroy(MaxHeap *heap);

int heap_size(const MaxHeap *heap);
int heap_contains(const MaxHeap *heap, const char *key);

/* Insert a new key, or UPDATE the priority if the key already exists.
 * O(log n). Returns 1 on success, 0 on failure. */
int heap_set(MaxHeap *heap, const char *key, double priority);

int heap_get_priority(const MaxHeap *heap, const char *key, double *out);
int heap_peek_max(const MaxHeap *heap, HeapItem *out);
int heap_extract_max(MaxHeap *heap, HeapItem *out);     /* O(log n) */
int heap_remove(MaxHeap *heap, const char *key);        /* O(log n) */

/* Copies up to k highest items (best first) into out[]. The heap itself is
 * not changed. Returns how many were copied. O(n + k log n). */
int heap_top_k(const MaxHeap *heap, int k, HeapItem *out);

/* Self-check used by the tests: 1 if the heap rule holds and the index map
 * agrees with the array, otherwise 0. */
int heap_check_invariants(const MaxHeap *heap);

#endif
