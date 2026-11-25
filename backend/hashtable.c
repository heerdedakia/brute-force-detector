/*
 * hashtable.c - separate-chaining hash table (see hashtable.h).
 *
 * Hash function: djb2  (hash = hash * 33 + next_character).
 * Load factor : when count > 75% of bucket_count we double the buckets
 *               and re-link every node, so chains stay short and the
 *               average lookup stays O(1).
 *
 * Memory: every node is one malloc, freed in ht_remove / ht_destroy.
 */
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

/* Turn a text key into a bucket number. */
static unsigned long hash_key(const char *key) {
    unsigned long hash = 5381;
    for (int i = 0; key[i] != '\0'; i++) {
        hash = hash * 33 + (unsigned char)key[i];
    }
    return hash;
}

static int key_is_valid(const char *key) {
    return key != NULL && strlen(key) < HT_KEY_MAX;
}

HashTable *ht_create(int initial_bucket_count) {
    if (initial_bucket_count < 1) initial_bucket_count = 1;

    HashTable *table = (HashTable *)malloc(sizeof(HashTable));
    if (table == NULL) return NULL;

    /* calloc fills with zeros, i.e. every bucket starts as an empty list (NULL) */
    table->buckets = (HashNode **)calloc((size_t)initial_bucket_count, sizeof(HashNode *));
    if (table->buckets == NULL) {
        free(table);
        return NULL;
    }
    table->bucket_count = initial_bucket_count;
    table->count = 0;
    return table;
}

void ht_destroy(HashTable *table, HtFreeFn free_value) {
    if (table == NULL) return;
    for (int b = 0; b < table->bucket_count; b++) {
        HashNode *node = table->buckets[b];
        while (node != NULL) {
            HashNode *next = node->next;       /* save before freeing */
            if (free_value != NULL) free_value(node->value);
            free(node);
            node = next;
        }
    }
    free(table->buckets);
    free(table);
}

/* Find the node for a key, or NULL. Walks one chain only. */
static HashNode *find_node(const HashTable *table, const char *key) {
    unsigned long bucket = hash_key(key) % (unsigned long)table->bucket_count;
    HashNode *node = table->buckets[bucket];
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) return node;
        node = node->next;
    }
    return NULL;
}

/* Double the bucket array and move every node to its new bucket.
 * Nodes are re-linked, not copied, so no node memory is allocated here. */
static void resize(HashTable *table) {
    int new_count = table->bucket_count * 2;
    HashNode **new_buckets = (HashNode **)calloc((size_t)new_count, sizeof(HashNode *));
    if (new_buckets == NULL) return;           /* keep working with the old size */

    for (int b = 0; b < table->bucket_count; b++) {
        HashNode *node = table->buckets[b];
        while (node != NULL) {
            HashNode *next = node->next;
            unsigned long nb = hash_key(node->key) % (unsigned long)new_count;
            node->next = new_buckets[nb];      /* insert at head of new chain */
            new_buckets[nb] = node;
            node = next;
        }
    }
    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_count;
}

int ht_put(HashTable *table, const char *key, void *value) {
    if (table == NULL || !key_is_valid(key)) return 0;

    HashNode *existing = find_node(table, key);
    if (existing != NULL) {                    /* key already there: replace value */
        existing->value = value;
        return 1;
    }

    HashNode *node = (HashNode *)malloc(sizeof(HashNode));
    if (node == NULL) return 0;
    strcpy(node->key, key);                    /* safe: length checked above */
    node->value = value;

    unsigned long bucket = hash_key(key) % (unsigned long)table->bucket_count;
    node->next = table->buckets[bucket];       /* insert at head: O(1) */
    table->buckets[bucket] = node;
    table->count++;

    if (table->count * 4 > table->bucket_count * 3) resize(table);
    return 1;
}

void *ht_get(const HashTable *table, const char *key) {
    if (table == NULL || !key_is_valid(key)) return NULL;
    HashNode *node = find_node(table, key);
    return node == NULL ? NULL : node->value;
}

int ht_contains(const HashTable *table, const char *key) {
    if (table == NULL || !key_is_valid(key)) return 0;
    return find_node(table, key) != NULL;
}

int ht_remove(HashTable *table, const char *key, void **removed_value) {
    if (table == NULL || !key_is_valid(key)) return 0;

    unsigned long bucket = hash_key(key) % (unsigned long)table->bucket_count;
    HashNode *previous = NULL;
    HashNode *node = table->buckets[bucket];

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            if (previous == NULL) table->buckets[bucket] = node->next;  /* was head */
            else                  previous->next = node->next;          /* bypass   */
            if (removed_value != NULL) *removed_value = node->value;
            free(node);
            table->count--;
            return 1;
        }
        previous = node;
        node = node->next;
    }
    return 0;
}

int ht_count(const HashTable *table) { return table == NULL ? 0 : table->count; }

void ht_for_each(const HashTable *table, HtVisitFn visit, void *context) {
    if (table == NULL || visit == NULL) return;
    for (int b = 0; b < table->bucket_count; b++) {
        for (HashNode *node = table->buckets[b]; node != NULL; node = node->next) {
            visit(node->key, node->value, context);
        }
    }
}
