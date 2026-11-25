/*
 * linkedlist.c - capped, newest-first alert list (see linkedlist.h).
 *
 * Memory: one malloc per node (in alert_list_add), freed when the node is
 * trimmed off the tail, in alert_list_clear, or in alert_list_destroy.
 */
#include <stdlib.h>
#include <string.h>
#include "linkedlist.h"

AlertList *alert_list_create(int max_size) {
    if (max_size < 1) max_size = 1;
    AlertList *list = (AlertList *)malloc(sizeof(AlertList));
    if (list == NULL) return NULL;
    list->head = NULL;
    list->size = 0;
    list->max_size = max_size;
    list->next_id = 1;
    return list;
}

void alert_list_clear(AlertList *list) {
    if (list == NULL) return;
    AlertNode *node = list->head;
    while (node != NULL) {
        AlertNode *next = node->next;      /* save before freeing */
        free(node);
        node = next;
    }
    list->head = NULL;
    list->size = 0;
}

void alert_list_destroy(AlertList *list) {
    alert_list_clear(list);
    free(list);
}

/* Remove the last node. We must walk to the node BEFORE the tail because a
 * singly linked list has no back pointers: O(n), but n <= max_size. */
static void remove_tail(AlertList *list) {
    if (list->head == NULL) return;
    if (list->head->next == NULL) {        /* only one node */
        free(list->head);
        list->head = NULL;
        list->size = 0;
        return;
    }
    AlertNode *before_tail = list->head;
    while (before_tail->next->next != NULL) before_tail = before_tail->next;
    free(before_tail->next);
    before_tail->next = NULL;
    list->size--;
}

int alert_list_add(AlertList *list, const AlertNode *alert) {
    if (list == NULL || alert == NULL) return 0;
    AlertNode *node = (AlertNode *)malloc(sizeof(AlertNode));
    if (node == NULL) return 0;

    *node = *alert;                        /* copy all fields */
    node->ip[ALERT_IP_MAX - 1] = '\0';     /* make sure strings are terminated */
    node->username[ALERT_USER_MAX - 1] = '\0';
    node->category[ALERT_CATEGORY_MAX - 1] = '\0';
    node->severity[sizeof(node->severity) - 1] = '\0';
    node->message[ALERT_MESSAGE_MAX - 1] = '\0';
    node->id = list->next_id++;

    node->next = list->head;               /* insert at head: O(1) */
    list->head = node;
    list->size++;

    if (list->size > list->max_size) remove_tail(list);
    return node->id;
}

int alert_list_size(const AlertList *list) { return list == NULL ? 0 : list->size; }

const AlertNode *alert_list_get(const AlertList *list, int i) {
    if (list == NULL || i < 0) return NULL;
    const AlertNode *node = list->head;
    while (node != NULL && i > 0) {
        node = node->next;
        i--;
    }
    return node;
}

const AlertNode *alert_list_find(const AlertList *list, int id) {
    for (const AlertNode *node = list == NULL ? NULL : list->head; node != NULL; node = node->next)
        if (node->id == id) return node;
    return NULL;
}
