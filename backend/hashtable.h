/*
 * hashtable.h - Hash table with SEPARATE CHAINING.
 *
 * Purpose : look up a record by a text key (an IP address or a username)
 *           in O(1) average time.
 * Idea    : the key is turned into a number (hash) that picks one of the
 *           "buckets". Each bucket is a singly linked list. Two keys that
 *           land in the same bucket (a collision) simply sit in the same list.
 *
 * The table stores a void* value. The CALLER decides what the value is
 * (an IpRecord, a UserStats, an int*, ...).
 * Keys are copied into the table. Keys must be shorter than HT_KEY_MAX.
 */
#ifndef HASHTABLE_H
#define HASHTABLE_H

#define HT_KEY_MAX 64

typedef struct HashNode {
    char key[HT_KEY_MAX];
    void *value;
    struct HashNode *next;      /* next node in the same bucket (collision chain) */
} HashNode;

typedef struct {
    HashNode **buckets;         /* array of list heads                      */
    int bucket_count;           /* length of the buckets array              */
    int count;                  /* number of keys stored                    */
} HashTable;

typedef void (*HtVisitFn)(const char *key, void *value, void *context);
typedef void (*HtFreeFn)(void *value);

HashTable *ht_create(int initial_bucket_count);

/* Frees every node. If free_value is not NULL it is called on each value. */
void ht_destroy(HashTable *table, HtFreeFn free_value);

/* Insert a new key, or replace the value of an existing key.
 * (The old value is NOT freed - use ht_get first if you need it.)
 * Returns 1 on success, 0 on failure (bad key / out of memory). */
int ht_put(HashTable *table, const char *key, void *value);

/* Returns the value, or NULL if the key is missing. */
void *ht_get(const HashTable *table, const char *key);
int   ht_contains(const HashTable *table, const char *key);

/* Removes a key. If removed_value is not NULL it receives the stored value
 * so the caller can free it. Returns 1 if removed, 0 if the key was missing. */
int ht_remove(HashTable *table, const char *key, void **removed_value);

int  ht_count(const HashTable *table);

/* Calls visit(key, value, context) once for every entry. Do not add or
 * remove entries from inside the callback. */
void ht_for_each(const HashTable *table, HtVisitFn visit, void *context);

#endif
