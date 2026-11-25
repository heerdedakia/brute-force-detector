/*
 * stack.h - ARRAY-BASED STACK of old Settings (bonus data structure).
 *
 * Purpose : "Undo" on the Settings page. Before new settings are applied,
 *           the current ones are pushed. Undo pops the most recent copy:
 *           Last In, First Out is exactly the order undo needs.
 * Size    : fixed capacity. When full, the OLDEST copy (the bottom) is
 *           thrown away so the most recent changes can always be undone.
 */
#ifndef STACK_H
#define STACK_H

#include "settings.h"

#define SETTINGS_STACK_CAPACITY 20

typedef struct {
    Settings items[SETTINGS_STACK_CAPACITY];   /* items[top-1] is the top */
    int top;                                   /* number of stored items  */
} SettingsStack;

void stack_init(SettingsStack *stack);
int  stack_is_empty(const SettingsStack *stack);
int  stack_is_full(const SettingsStack *stack);
int  stack_size(const SettingsStack *stack);

/* Always succeeds for a valid stack (drops the bottom item when full).
 * Returns 1 on success, 0 if stack/item is NULL. */
int  stack_push(SettingsStack *stack, const Settings *item);
int  stack_pop(SettingsStack *stack, Settings *out);         /* 1 ok, 0 empty */
int  stack_peek(const SettingsStack *stack, Settings *out);  /* 1 ok, 0 empty */

#endif
