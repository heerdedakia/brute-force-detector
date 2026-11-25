/*
 * parser.h - reads login events in CSV form.
 *
 * One event per line:
 *     2026-11-20 12:30:15,192.168.1.10,admin,FAILED
 * (status is FAILED or SUCCESS, upper or lower case).
 * Blank lines and lines starting with '#' are ignored.
 * Any other line that cannot be read is SKIPPED and COUNTED, never fatal.
 */
#ifndef PARSER_H
#define PARSER_H

#define EVENT_IP_MAX   40     /* enough for an IPv4 address "255.255.255.255" */
#define EVENT_USER_MAX 33     /* usernames up to 32 characters                */
#define PARSER_LINE_MAX 512

typedef struct {
    long long timestamp;            /* seconds since 1970-01-01 00:00:00 UTC */
    char ip[EVENT_IP_MAX];
    char username[EVENT_USER_MAX];
    int success;                    /* 1 = SUCCESS, 0 = FAILED               */
} LoginEvent;

/* A growable array of events (doubles its capacity when full). */
typedef struct {
    LoginEvent *items;
    int count;
    int capacity;
} EventList;

typedef struct {
    int lines_read;      /* every line seen                         */
    int events_ok;       /* lines turned into events                */
    int ignored;         /* blank lines and # comments              */
    int malformed;       /* lines skipped because they were invalid */
    int first_bad_line;  /* line number of the first bad line, or 0 */
} ParseStats;

/* ---- time helpers (portable, no timegm needed) ---- */

/* Days from 1970-01-01 to the given date (negative before 1970). */
long long days_from_civil(int year, int month, int day);
/* Inverse of days_from_civil. */
void civil_from_days(long long days, int *year, int *month, int *day);
/* "YYYY-MM-DD HH:MM:SS" -> epoch seconds. Returns 1 ok, 0 invalid. */
int parse_datetime(const char *text, long long *out);
/* epoch seconds -> "YYYY-MM-DD HH:MM:SS" (buffer at least 20 bytes). */
void format_datetime(long long epoch, char *buffer, int buffer_size);

/* Safe string copy: copies at most dest_size-1 characters and ALWAYS ends
 * dest with '\0' (unlike strncpy). Used by every module that copies text. */
void copy_text(char *dest, int dest_size, const char *src);

/* ---- parsing ---- */

/* Parses ONE line (with or without "\n"). Returns 1 ok, 0 malformed. */
int parse_line(const char *line, LoginEvent *out);
/* Formats an event back into one CSV line (no newline). */
void event_to_csv(const LoginEvent *event, char *buffer, int buffer_size);

void event_list_init(EventList *list);
void event_list_free(EventList *list);
int  event_list_add(EventList *list, const LoginEvent *event);   /* 1 ok, 0 no memory */

/* Parses a whole text buffer (for example an uploaded file) line by line,
 * appending good events to list. stats may be NULL. Returns events added. */
int parse_text(const char *text, EventList *list, ParseStats *stats);

/* Reads a file. Returns events added, or -1 if the file cannot be opened. */
int parse_file(const char *path, EventList *list, ParseStats *stats);

#endif
