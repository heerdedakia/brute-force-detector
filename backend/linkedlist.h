/*
 * linkedlist.h - SINGLY LINKED LIST of recent alerts, newest first.
 *
 * Purpose : the "Recent alerts" panel of the dashboard.
 * Why     : a new alert is inserted at the HEAD in O(1), and the list is
 *           naturally ordered newest -> oldest, which is exactly how the
 *           dashboard shows it. The list is capped (max_size); when it grows
 *           past the cap the oldest node (the tail) is removed.
 */
#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#define ALERT_IP_MAX       64
#define ALERT_USER_MAX     64
#define ALERT_CATEGORY_MAX 32
#define ALERT_MESSAGE_MAX  160

typedef struct AlertNode {
    int id;                               /* increasing number, 1, 2, 3 ...   */
    long long time;                       /* simulation time of the alert     */
    char ip[ALERT_IP_MAX];                /* may be "" for username alerts    */
    char username[ALERT_USER_MAX];
    char category[ALERT_CATEGORY_MAX];    /* "Fast brute-force", "Ban", ...   */
    char severity[16];                    /* "low" .. "critical"              */
    double score;
    char message[ALERT_MESSAGE_MAX];
    struct AlertNode *next;               /* next OLDER alert                 */
} AlertNode;

typedef struct {
    AlertNode *head;      /* newest alert (NULL when empty) */
    int size;
    int max_size;
    int next_id;
} AlertList;

AlertList *alert_list_create(int max_size);
void alert_list_destroy(AlertList *list);
void alert_list_clear(AlertList *list);      /* frees all nodes, keeps list */

/* Copies *alert into a new node at the head. The id and next fields of the
 * input are ignored; the list assigns the id. Returns the new id, or 0 on
 * failure. */
int alert_list_add(AlertList *list, const AlertNode *alert);

int alert_list_size(const AlertList *list);

/* i = 0 is the newest. Returns NULL if out of range. O(i). */
const AlertNode *alert_list_get(const AlertList *list, int i);

/* Returns the node with that id, or NULL. O(n). */
const AlertNode *alert_list_find(const AlertList *list, int id);

#endif
