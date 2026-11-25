/*
 * parser.c - CSV login-event parser (see parser.h).
 *
 * Validation done for every line:
 *   - exactly 4 comma-separated fields
 *   - a real date and time  (month 1-12, day valid for that month incl. leap
 *     years, hour 0-23, minute 0-59, second 0-59)
 *   - an IPv4 address: four numbers 0-255 separated by dots
 *   - a username of 1-32 printable characters without spaces
 *   - status FAILED or SUCCESS (case does not matter)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "parser.h"

/* ================= time helpers ================= */

/*
 * days_from_civil: the well-known algorithm by Howard Hinnant.
 * Idea: start the year in MARCH, so February (with its leap day) is the LAST
 * month. Then every month length follows a fixed pattern and the leap day
 * never sits in the middle of a year. "era" = a 400-year cycle, which has
 * exactly 146097 days.
 */
long long days_from_civil(int year, int month, int day) {
    long long y = (long long)year - (month <= 2 ? 1 : 0);
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long year_of_era = y - era * 400;                              /* 0..399   */
    long long month_from_march = (month + 9) % 12;                      /* Mar = 0  */
    long long day_of_year = (153 * month_from_march + 2) / 5 + day - 1; /* 0..365   */
    long long day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + day_of_era - 719468;   /* 719468 = days from 0000-03-01 to 1970-01-01 */
}

void civil_from_days(long long days, int *year, int *month, int *day) {
    days += 719468;
    long long era = (days >= 0 ? days : days - 146096) / 146097;
    long long day_of_era = days - era * 146097;
    long long year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    long long day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    long long month_from_march = (5 * day_of_year + 2) / 153;
    *day = (int)(day_of_year - (153 * month_from_march + 2) / 5 + 1);
    *month = (int)(month_from_march < 10 ? month_from_march + 3 : month_from_march - 9);
    *year = (int)(year_of_era + era * 400 + (*month <= 2 ? 1 : 0));
}

static int is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

static int days_in_month(int year, int month) {
    static const int lengths[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && is_leap_year(year)) return 29;
    return lengths[month - 1];
}

/* Reads exactly 'digits' decimal digits from text. */
static int read_number(const char *text, int digits, int *out) {
    int value = 0;
    for (int i = 0; i < digits; i++) {
        if (!isdigit((unsigned char)text[i])) return 0;
        value = value * 10 + (text[i] - '0');
    }
    *out = value;
    return 1;
}

int parse_datetime(const char *text, long long *out) {
    int year, month, day, hour, minute, second;
    /* Expected layout: YYYY-MM-DD HH:MM:SS  (19 characters) */
    if (text == NULL || strlen(text) != 19) return 0;
    if (text[4] != '-' || text[7] != '-' || text[10] != ' ' || text[13] != ':' || text[16] != ':')
        return 0;
    if (!read_number(text, 4, &year) || !read_number(text + 5, 2, &month) ||
        !read_number(text + 8, 2, &day) || !read_number(text + 11, 2, &hour) ||
        !read_number(text + 14, 2, &minute) || !read_number(text + 17, 2, &second))
        return 0;
    if (year < 1970 || month < 1 || month > 12) return 0;
    if (day < 1 || day > days_in_month(year, month)) return 0;
    if (hour > 23 || minute > 59 || second > 59) return 0;

    *out = days_from_civil(year, month, day) * 86400LL + hour * 3600LL + minute * 60LL + second;
    return 1;
}

void format_datetime(long long epoch, char *buffer, int buffer_size) {
    if (buffer == NULL || buffer_size <= 0) return;
    long long days = epoch / 86400;
    long long seconds_of_day = epoch % 86400;
    if (seconds_of_day < 0) { seconds_of_day += 86400; days--; }   /* before 1970 */
    int year, month, day;
    civil_from_days(days, &year, &month, &day);
    snprintf(buffer, (size_t)buffer_size, "%04d-%02d-%02d %02d:%02d:%02d", year, month, day,
             (int)(seconds_of_day / 3600), (int)(seconds_of_day / 60 % 60), (int)(seconds_of_day % 60));
}

void copy_text(char *dest, int dest_size, const char *src) {
    int i = 0;
    if (dest == NULL || dest_size <= 0) return;
    if (src != NULL)
        for (; i < dest_size - 1 && src[i] != '\0'; i++) dest[i] = src[i];
    dest[i] = '\0';
}

/* ================= field validation ================= */

static int is_valid_ipv4(const char *ip) {
    int parts = 0;
    const char *p = ip;
    while (parts < 4) {
        int value = 0, digits = 0;
        while (isdigit((unsigned char)*p)) {
            value = value * 10 + (*p - '0');
            digits++;
            p++;
            if (digits > 3) return 0;
        }
        if (digits == 0 || value > 255) return 0;
        parts++;
        if (parts < 4) {
            if (*p != '.') return 0;
            p++;
        }
    }
    return *p == '\0';
}

static int is_valid_username(const char *name) {
    size_t length = strlen(name);
    if (length == 0 || length >= EVENT_USER_MAX) return 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isgraph(c) || c == '"' || c == '\\') return 0;  /* no spaces, quotes, controls */
    }
    return 1;
}

/* Case-insensitive compare of two words. */
static int same_word(const char *a, const char *b) {
    while (*a && *b) {
        if (toupper((unsigned char)*a) != toupper((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Remove spaces, tabs, \r and \n from both ends, in place. */
static void trim(char *text) {
    size_t length = strlen(text);
    while (length > 0 && isspace((unsigned char)text[length - 1])) text[--length] = '\0';
    size_t start = 0;
    while (isspace((unsigned char)text[start])) start++;
    if (start > 0) memmove(text, text + start, length - start + 1);
}

/* ================= line parsing ================= */

int parse_line(const char *line, LoginEvent *out) {
    char copy[PARSER_LINE_MAX];
    char *fields[4];
    int field_count = 0;

    if (line == NULL || out == NULL || strlen(line) >= PARSER_LINE_MAX) return 0;
    strcpy(copy, line);

    /* Split on commas by hand (strtok would merge empty fields like ",,"). */
    fields[field_count++] = copy;
    for (char *p = copy; *p != '\0'; p++) {
        if (*p == ',') {
            if (field_count == 4) return 0;      /* too many fields */
            *p = '\0';
            fields[field_count++] = p + 1;
        }
    }
    if (field_count != 4) return 0;
    for (int i = 0; i < 4; i++) trim(fields[i]);

    LoginEvent event;
    memset(&event, 0, sizeof event);
    if (!parse_datetime(fields[0], &event.timestamp)) return 0;
    if (strlen(fields[1]) >= EVENT_IP_MAX || !is_valid_ipv4(fields[1])) return 0;
    if (!is_valid_username(fields[2])) return 0;
    if (same_word(fields[3], "FAILED"))       event.success = 0;
    else if (same_word(fields[3], "SUCCESS")) event.success = 1;
    else return 0;

    strcpy(event.ip, fields[1]);
    strcpy(event.username, fields[2]);
    *out = event;
    return 1;
}

void event_to_csv(const LoginEvent *event, char *buffer, int buffer_size) {
    char when[24];
    format_datetime(event->timestamp, when, sizeof when);
    snprintf(buffer, (size_t)buffer_size, "%s,%s,%s,%s", when, event->ip, event->username,
             event->success ? "SUCCESS" : "FAILED");
}

/* ================= event list ================= */

void event_list_init(EventList *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void event_list_free(EventList *list) {
    if (list == NULL) return;
    free(list->items);
    event_list_init(list);
}

int event_list_add(EventList *list, const LoginEvent *event) {
    /* Copy the event FIRST: if 'event' points inside list->items, realloc
     * below may move that memory and the pointer would become invalid. */
    LoginEvent copy = *event;
    if (list->count == list->capacity) {
        int new_capacity = list->capacity == 0 ? 64 : list->capacity * 2;
        /* realloc keeps the old data; if it fails the old block is untouched */
        LoginEvent *bigger = (LoginEvent *)realloc(list->items, sizeof(LoginEvent) * (size_t)new_capacity);
        if (bigger == NULL) return 0;
        list->items = bigger;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = copy;
    return 1;
}

/* ================= whole inputs ================= */

/* Handles one raw line and updates the statistics. */
static void handle_line(const char *raw, EventList *list, ParseStats *stats) {
    LoginEvent event;
    int i = 0;
    stats->lines_read++;

    /* skip leading blanks to see whether the line is empty or a comment */
    while (raw[i] == ' ' || raw[i] == '\t') i++;
    if (raw[i] == '\0' || raw[i] == '\r' || raw[i] == '\n' || raw[i] == '#') {
        stats->ignored++;
        return;
    }
    if (parse_line(raw, &event) && event_list_add(list, &event)) {
        stats->events_ok++;
    } else {
        stats->malformed++;
        if (stats->first_bad_line == 0) stats->first_bad_line = stats->lines_read;
    }
}

int parse_text(const char *text, EventList *list, ParseStats *stats) {
    ParseStats local = {0, 0, 0, 0, 0};
    char line[PARSER_LINE_MAX];
    if (stats == NULL) stats = &local;
    int before = stats->events_ok;
    if (text == NULL || list == NULL) return 0;

    const char *p = text;
    while (*p != '\0') {
        int length = 0;
        int too_long = 0;
        while (*p != '\0' && *p != '\n') {
            if (length < PARSER_LINE_MAX - 1) line[length++] = *p;
            else too_long = 1;                 /* keep reading to the end of the line */
            p++;
        }
        if (*p == '\n') p++;
        line[length] = '\0';
        if (too_long) {                        /* a giant line is always malformed */
            stats->lines_read++;
            stats->malformed++;
            if (stats->first_bad_line == 0) stats->first_bad_line = stats->lines_read;
        } else {
            handle_line(line, list, stats);
        }
    }
    return stats->events_ok - before;
}

int parse_file(const char *path, EventList *list, ParseStats *stats) {
    ParseStats local = {0, 0, 0, 0, 0};
    char line[PARSER_LINE_MAX];
    if (stats == NULL) stats = &local;
    int before = stats->events_ok;

    FILE *file = fopen(path, "rb");   /* binary mode: we strip \r ourselves on Windows */
    if (file == NULL) return -1;

    while (fgets(line, sizeof line, file) != NULL) {
        size_t length = strlen(line);
        if (length == sizeof line - 1 && line[length - 1] != '\n') {
            /* line longer than the buffer: count it once and skip the rest */
            int c;
            while ((c = fgetc(file)) != EOF && c != '\n') { }
            stats->lines_read++;
            stats->malformed++;
            if (stats->first_bad_line == 0) stats->first_bad_line = stats->lines_read;
            continue;
        }
        handle_line(line, list, stats);
    }
    fclose(file);
    return stats->events_ok - before;
}
