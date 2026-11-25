/*
 * heap.c - max heap with an index map (see heap.h).
 *
 * Memory: items array (doubles when full), one HashTable, and one small
 * malloc'd int per stored key inside that table. heap_destroy frees them all.
 */
#include <stdlib.h>
#include <string.h>
#include "heap.h"

/* ---- index map helpers: key -> position in items[] ---- */

static int get_index(const MaxHeap *heap, const char *key) {
    int *position = (int *)ht_get(heap->index_of, key);
    return position == NULL ? -1 : *position;
}

static void set_index(MaxHeap *heap, const char *key, int index) {
    int *position = (int *)ht_get(heap->index_of, key);
    if (position != NULL) *position = index;      /* key already mapped */
}

/* ---- swapping two items keeps the map correct ---- */

static void swap_items(MaxHeap *heap, int a, int b) {
    HeapItem temp = heap->items[a];
    heap->items[a] = heap->items[b];
    heap->items[b] = temp;
    set_index(heap, heap->items[a].key, a);
    set_index(heap, heap->items[b].key, b);
}

/* Move item i UP while it is bigger than its parent. */
static void sift_up(MaxHeap *heap, int i) {
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (heap->items[i].priority <= heap->items[parent].priority) break;
        swap_items(heap, i, parent);
        i = parent;
    }
}

/* Move item i DOWN while a child is bigger than it. */
static void sift_down(MaxHeap *heap, int i) {
    for (;;) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        int largest = i;
        if (left < heap->size && heap->items[left].priority > heap->items[largest].priority)
            largest = left;
        if (right < heap->size && heap->items[right].priority > heap->items[largest].priority)
            largest = right;
        if (largest == i) break;
        swap_items(heap, i, largest);
        i = largest;
    }
}

MaxHeap *heap_create(int initial_capacity) {
    if (initial_capacity < 1) initial_capacity = 1;

    MaxHeap *heap = (MaxHeap *)malloc(sizeof(MaxHeap));
    if (heap == NULL) return NULL;

    heap->items = (HeapItem *)malloc(sizeof(HeapItem) * (size_t)initial_capacity);
    heap->index_of = ht_create(16);
    if (heap->items == NULL || heap->index_of == NULL) {
        free(heap->items);
        ht_destroy(heap->index_of, NULL);
        free(heap);
        return NULL;
    }
    heap->size = 0;
    heap->capacity = initial_capacity;
    return heap;
}

void heap_destroy(MaxHeap *heap) {
    if (heap == NULL) return;
    ht_destroy(heap->index_of, free);   /* frees every int* stored as a value */
    free(heap->items);
    free(heap);
}

int heap_size(const MaxHeap *heap) { return heap == NULL ? 0 : heap->size; }

int heap_contains(const MaxHeap *heap, const char *key) {
    return heap != NULL && ht_contains(heap->index_of, key);
}

int heap_set(MaxHeap *heap, const char *key, double priority) {
    if (heap == NULL || key == NULL) return 0;

    int index = get_index(heap, key);
    if (index >= 0) {
        /* UPDATE: change the score, then move up or down as needed. */
        double old_priority = heap->items[index].priority;
        heap->items[index].priority = priority;
        if (priority > old_priority) sift_up(heap, index);
        else if (priority < old_priority) sift_down(heap, index);
        return 1;
    }

    /* INSERT: grow the array if full. */
    if (heap->size == heap->capacity) {
        HeapItem *bigger = (HeapItem *)realloc(heap->items,
                               sizeof(HeapItem) * (size_t)heap->capacity * 2);
        if (bigger == NULL) return 0;
        heap->items = bigger;
        heap->capacity *= 2;
    }

    int *position = (int *)malloc(sizeof(int));
    if (position == NULL) return 0;
    *position = heap->size;
    if (!ht_put(heap->index_of, key, position)) {   /* also rejects too-long keys */
        free(position);
        return 0;
    }

    strcpy(heap->items[heap->size].key, key);       /* length verified by ht_put */
    heap->items[heap->size].priority = priority;
    heap->size++;
    sift_up(heap, heap->size - 1);
    return 1;
}

int heap_get_priority(const MaxHeap *heap, const char *key, double *out) {
    if (heap == NULL || out == NULL) return 0;
    int index = get_index(heap, key);
    if (index < 0) return 0;
    *out = heap->items[index].priority;
    return 1;
}

int heap_peek_max(const MaxHeap *heap, HeapItem *out) {
    if (heap == NULL || heap->size == 0 || out == NULL) return 0;
    *out = heap->items[0];
    return 1;
}

/* Remove the item at position `index` (shared by extract_max and remove). */
static void remove_at(MaxHeap *heap, int index) {
    void *stored = NULL;
    ht_remove(heap->index_of, heap->items[index].key, &stored);
    free(stored);                                   /* the int* for this key */

    int last = heap->size - 1;
    if (index != last) {
        heap->items[index] = heap->items[last];     /* fill the hole with the last item */
        set_index(heap, heap->items[index].key, index);
    }
    heap->size--;

    if (index < heap->size) {                       /* the moved item may belong up or down */
        sift_up(heap, index);
        sift_down(heap, get_index(heap, heap->items[index].key));
    }
}

int heap_extract_max(MaxHeap *heap, HeapItem *out) {
    if (heap == NULL || heap->size == 0) return 0;
    if (out != NULL) *out = heap->items[0];
    remove_at(heap, 0);
    return 1;
}

int heap_remove(MaxHeap *heap, const char *key) {
    if (heap == NULL) return 0;
    int index = get_index(heap, key);
    if (index < 0) return 0;
    remove_at(heap, index);
    return 1;
}

/* Same sift-down but on a plain array copy (no index map involved). */
static void sift_down_copy(HeapItem *items, int size, int i) {
    for (;;) {
        int left = 2 * i + 1, right = 2 * i + 2, largest = i;
        if (left < size && items[left].priority > items[largest].priority) largest = left;
        if (right < size && items[right].priority > items[largest].priority) largest = right;
        if (largest == i) break;
        HeapItem temp = items[i]; items[i] = items[largest]; items[largest] = temp;
        i = largest;
    }
}

int heap_top_k(const MaxHeap *heap, int k, HeapItem *out) {
    if (heap == NULL || out == NULL || k <= 0 || heap->size == 0) return 0;

    /* Work on a copy so the real heap is untouched. */
    HeapItem *copy = (HeapItem *)malloc(sizeof(HeapItem) * (size_t)heap->size);
    if (copy == NULL) return 0;
    memcpy(copy, heap->items, sizeof(HeapItem) * (size_t)heap->size);

    int copy_size = heap->size;
    int taken = 0;
    while (taken < k && copy_size > 0) {
        out[taken++] = copy[0];                     /* current maximum */
        copy[0] = copy[copy_size - 1];
        copy_size--;
        sift_down_copy(copy, copy_size, 0);
    }
    free(copy);
    return taken;
}

int heap_check_invariants(const MaxHeap *heap) {
    if (heap == NULL) return 0;
    if (ht_count(heap->index_of) != heap->size) return 0;
    for (int i = 0; i < heap->size; i++) {
        if (get_index(heap, heap->items[i].key) != i) return 0;          /* map agrees */
        if (i > 0 && heap->items[i].priority > heap->items[(i - 1) / 2].priority)
            return 0;                                                    /* heap rule  */
    }
    return 1;
}
