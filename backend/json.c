/*
 * json.c - string builder and form decoding (see json.h).
 * Memory: the buffer doubles when it is full (amortized O(1) appends);
 * sb_free releases it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <math.h>
#include "json.h"

void sb_init(StrBuf *sb) {
    sb->data = NULL;
    sb->length = 0;
    sb->capacity = 0;
    sb->failed = 0;
}

void sb_free(StrBuf *sb) {
    free(sb->data);
    sb_init(sb);
}

/* Make room for 'extra' more bytes plus the final '\0'. */
static int ensure(StrBuf *sb, size_t extra) {
    if (sb->failed) return 0;
    size_t needed = sb->length + extra + 1;
    if (needed <= sb->capacity) return 1;
    size_t new_capacity = sb->capacity == 0 ? 256 : sb->capacity;
    while (new_capacity < needed) new_capacity *= 2;
    char *bigger = (char *)realloc(sb->data, new_capacity);
    if (bigger == NULL) {
        sb->failed = 1;
        return 0;
    }
    sb->data = bigger;
    sb->capacity = new_capacity;
    return 1;
}

void sb_append_bytes(StrBuf *sb, const char *bytes, size_t count) {
    if (!ensure(sb, count)) return;
    memcpy(sb->data + sb->length, bytes, count);
    sb->length += count;
    sb->data[sb->length] = '\0';
}

void sb_append(StrBuf *sb, const char *text) {
    if (text != NULL) sb_append_bytes(sb, text, strlen(text));
}

void sb_appendf(StrBuf *sb, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int needed = vsnprintf(NULL, 0, format, args);   /* first: measure */
    va_end(args);
    if (needed < 0 || !ensure(sb, (size_t)needed)) return;
    va_start(args, format);
    vsnprintf(sb->data + sb->length, (size_t)needed + 1, format, args);  /* then: write */
    va_end(args);
    sb->length += (size_t)needed;
}

void sb_json_string(StrBuf *sb, const char *text) {
    sb_append(sb, "\"");
    for (const unsigned char *p = (const unsigned char *)(text ? text : ""); *p != '\0'; p++) {
        switch (*p) {
        case '"':  sb_append(sb, "\\\""); break;
        case '\\': sb_append(sb, "\\\\"); break;
        case '\n': sb_append(sb, "\\n"); break;
        case '\r': sb_append(sb, "\\r"); break;
        case '\t': sb_append(sb, "\\t"); break;
        default:
            if (*p < 0x20) sb_appendf(sb, "\\u%04x", *p);      /* other control chars */
            else sb_append_bytes(sb, (const char *)p, 1);
        }
    }
    sb_append(sb, "\"");
}

void sb_json_number(StrBuf *sb, double value) {
    if (isnan(value) || isinf(value)) sb_append(sb, "null");
    else sb_appendf(sb, "%.4g", value);
}

/* ---- form data ---- */

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int form_get(const char *body, const char *key, char *out, int out_size) {
    if (body == NULL || key == NULL || out == NULL || out_size <= 0) return 0;
    size_t key_length = strlen(key);
    const char *p = body;
    while (*p != '\0') {
        const char *pair_end = strchr(p, '&');
        if (pair_end == NULL) pair_end = p + strlen(p);
        if ((size_t)(pair_end - p) > key_length && strncmp(p, key, key_length) == 0 && p[key_length] == '=') {
            /* decode %XX and '+' into out */
            const char *v = p + key_length + 1;
            int n = 0;
            while (v < pair_end && n < out_size - 1) {
                if (*v == '+') { out[n++] = ' '; v++; }
                else if (*v == '%' && v + 2 < pair_end + 1 && hex_value(v[1]) >= 0 && hex_value(v[2]) >= 0) {
                    out[n++] = (char)(hex_value(v[1]) * 16 + hex_value(v[2]));
                    v += 3;
                } else out[n++] = *v++;
            }
            out[n] = '\0';
            return 1;
        }
        if ((size_t)(pair_end - p) == key_length && strncmp(p, key, key_length) == 0) {
            out[0] = '\0';                       /* "key" with no '=' */
            return 1;
        }
        p = *pair_end == '&' ? pair_end + 1 : pair_end;
    }
    return 0;
}

int form_get_int(const char *body, const char *key, int *out) {
    char text[32];
    char *end;
    if (!form_get(body, key, text, sizeof text) || text[0] == '\0') return 0;
    long value = strtol(text, &end, 10);
    if (*end != '\0' || value < -1000000000L || value > 1000000000L) return 0;
    *out = (int)value;
    return 1;
}

int form_get_double(const char *body, const char *key, double *out) {
    char text[32];
    char *end;
    if (!form_get(body, key, text, sizeof text) || text[0] == '\0') return 0;
    double value = strtod(text, &end);
    if (*end != '\0' || isnan(value) || isinf(value)) return 0;
    *out = value;
    return 1;
}
