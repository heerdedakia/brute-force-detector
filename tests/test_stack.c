/* Unit tests for the settings stack (Undo). Run: make test_stack */
#include <stdio.h>
#include <string.h>
#include "../backend/stack.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

/* stack.c does not need the real defaults; tests only use one field. */
static Settings with_ban(int seconds) {
    Settings s;
    memset(&s, 0, sizeof s);
    s.ban_duration = seconds;
    return s;
}

int main(void) {
    SettingsStack stack;
    Settings out;
    stack_init(&stack);

    printf("push / pop LIFO order\n");
    CHECK(stack_is_empty(&stack) && !stack_pop(&stack, &out) && !stack_peek(&stack, &out));
    for (int i = 1; i <= 5; i++) { Settings s = with_ban(i); CHECK(stack_push(&stack, &s)); }
    CHECK(stack_size(&stack) == 5);
    CHECK(stack_peek(&stack, &out) && out.ban_duration == 5);
    CHECK(stack_pop(&stack, &out) && out.ban_duration == 5);
    CHECK(stack_pop(&stack, &out) && out.ban_duration == 4);

    printf("full stack drops the oldest\n");
    stack_init(&stack);
    for (int i = 1; i <= SETTINGS_STACK_CAPACITY + 5; i++) { Settings s = with_ban(i); stack_push(&stack, &s); }
    CHECK(stack_is_full(&stack) && stack_size(&stack) == SETTINGS_STACK_CAPACITY);
    CHECK(stack_peek(&stack, &out) && out.ban_duration == SETTINGS_STACK_CAPACITY + 5);
    int last = 0;
    while (stack_pop(&stack, &out)) last = out.ban_duration;
    CHECK(last == 6);                       /* 1..5 were dropped */
    CHECK(stack_is_empty(&stack));

    printf("edge cases\n");
    CHECK(!stack_push(NULL, &out) && !stack_push(&stack, NULL));
    CHECK(stack_pop(&stack, NULL) == 0);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
