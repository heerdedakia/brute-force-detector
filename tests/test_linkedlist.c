/* Unit tests for the alert linked list. Run: make test_linkedlist */
#include <stdio.h>
#include <string.h>
#include "../backend/linkedlist.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static AlertNode make_alert(const char *ip, long long t) {
    AlertNode a;
    memset(&a, 0, sizeof a);
    strcpy(a.ip, ip);
    strcpy(a.category, "Test");
    strcpy(a.severity, "high");
    a.time = t;
    snprintf(a.message, sizeof a.message, "alert from %s", ip);
    return a;
}

static void test_newest_first(void) {
    printf("insert at head, newest first\n");
    AlertList *list = alert_list_create(10);
    CHECK(list != NULL && alert_list_size(list) == 0 && alert_list_get(list, 0) == NULL);
    AlertNode a = make_alert("1.1.1.1", 100);
    CHECK(alert_list_add(list, &a) == 1);
    a = make_alert("2.2.2.2", 200);
    CHECK(alert_list_add(list, &a) == 2);
    a = make_alert("3.3.3.3", 300);
    CHECK(alert_list_add(list, &a) == 3);
    CHECK(alert_list_size(list) == 3);
    CHECK(strcmp(alert_list_get(list, 0)->ip, "3.3.3.3") == 0);
    CHECK(strcmp(alert_list_get(list, 2)->ip, "1.1.1.1") == 0);
    CHECK(alert_list_get(list, 3) == NULL && alert_list_get(list, -1) == NULL);
    CHECK(alert_list_find(list, 2) != NULL && alert_list_find(list, 2)->time == 200);
    CHECK(alert_list_find(list, 99) == NULL);
    alert_list_destroy(list);
}

static void test_cap(void) {
    printf("cap removes the oldest (tail)\n");
    AlertList *list = alert_list_create(3);
    char ip[32];
    for (int i = 1; i <= 50; i++) {
        snprintf(ip, sizeof ip, "10.0.0.%d", i);
        AlertNode a = make_alert(ip, i);
        alert_list_add(list, &a);
        CHECK(alert_list_size(list) == (i < 3 ? i : 3));
    }
    CHECK(alert_list_get(list, 0)->time == 50);
    CHECK(alert_list_get(list, 2)->time == 48);
    CHECK(alert_list_find(list, 47) == NULL);       /* trimmed away */
    alert_list_clear(list);
    CHECK(alert_list_size(list) == 0 && list->head == NULL);
    AlertNode a = make_alert("9.9.9.9", 1);
    CHECK(alert_list_add(list, &a) == 51);          /* ids keep increasing */
    alert_list_destroy(list);
}

static void test_edge_cases(void) {
    printf("edge cases\n");
    CHECK(alert_list_add(NULL, NULL) == 0);
    CHECK(alert_list_size(NULL) == 0);
    alert_list_destroy(NULL);                        /* must not crash */
    AlertList *list = alert_list_create(0);          /* clamped to 1 */
    AlertNode a = make_alert("1.1.1.1", 1);
    memset(a.message, 'x', sizeof a.message);        /* unterminated input */
    alert_list_add(list, &a);
    alert_list_add(list, &a);
    CHECK(alert_list_size(list) == 1);
    CHECK(strlen(alert_list_get(list, 0)->message) == ALERT_MESSAGE_MAX - 1);
    alert_list_destroy(list);
}

int main(void) {
    test_newest_first();
    test_cap();
    test_edge_cases();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
