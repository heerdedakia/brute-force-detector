/*
 * json.h - a growable text buffer ("string builder") used to build JSON
 * and HTTP responses, plus small helpers for form data.
 */
#ifndef JSON_H
#define JSON_H

#include <stddef.h>

typedef struct {
    char *data;        /* always '\0'-terminated (when not NULL) */
    size_t length;
    size_t capacity;
    int failed;        /* 1 if memory ran out at some point       */
} StrBuf;

void sb_init(StrBuf *sb);
void sb_free(StrBuf *sb);
void sb_append(StrBuf *sb, const char *text);
void sb_append_bytes(StrBuf *sb, const char *bytes, size_t count);
void sb_appendf(StrBuf *sb, const char *format, ...);   /* like printf */

/* Appends text as a JSON string WITH quotes, escaping " \ and control chars. */
void sb_json_string(StrBuf *sb, const char *text);
/* Appends a number, or null for NaN / infinity (JSON has no NaN). */
void sb_json_number(StrBuf *sb, double value);

/* Form data "a=1&b=hello%20world": copies the decoded value of key into out.
 * Returns 1 if the key was found, 0 otherwise. */
int form_get(const char *body, const char *key, char *out, int out_size);
int form_get_int(const char *body, const char *key, int *out);
int form_get_double(const char *body, const char *key, double *out);

#endif
