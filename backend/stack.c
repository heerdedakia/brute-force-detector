/*
 * stack.c - fixed-size array stack (see stack.h). No dynamic memory at all:
 * the array lives inside the struct.
 */
#include <stddef.h>
#include "stack.h"

void stack_init(SettingsStack *stack) { if (stack != NULL) stack->top = 0; }
int  stack_is_empty(const SettingsStack *stack) { return stack == NULL || stack->top == 0; }
int  stack_is_full(const SettingsStack *stack)  { return stack != NULL && stack->top == SETTINGS_STACK_CAPACITY; }
int  stack_size(const SettingsStack *stack)     { return stack == NULL ? 0 : stack->top; }

int stack_push(SettingsStack *stack, const Settings *item) {
    if (stack == NULL || item == NULL) return 0;
    if (stack_is_full(stack)) {
        /* Drop the bottom (oldest) item by shifting everything down one.
         * O(capacity) = O(20), only when full. Push is O(1) otherwise. */
        for (int i = 1; i < SETTINGS_STACK_CAPACITY; i++)
            stack->items[i - 1] = stack->items[i];
        stack->top--;
    }
    stack->items[stack->top] = *item;
    stack->top++;
    return 1;
}

int stack_pop(SettingsStack *stack, Settings *out) {
    if (stack_is_empty(stack)) return 0;
    stack->top--;
    if (out != NULL) *out = stack->items[stack->top];
    return 1;
}

int stack_peek(const SettingsStack *stack, Settings *out) {
    if (stack_is_empty(stack) || out == NULL) return 0;
    *out = stack->items[stack->top - 1];
    return 1;
}
