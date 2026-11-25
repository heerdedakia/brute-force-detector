/* Unit tests for the CSV parser and the date functions. Run: make test_parser */
#include <stdio.h>
#include <string.h>
#include "../backend/parser.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void test_known_dates(void) {
    printf("known epoch values (checked against a reference implementation)\n");
    long long t;
    CHECK(parse_datetime("1970-01-01 00:00:00", &t) && t == 0);
    CHECK(parse_datetime("2026-11-20 12:30:15", &t) && t == 1795177815LL);
    CHECK(parse_datetime("2000-02-29 23:59:59", &t) && t == 951868799LL);   /* leap day */
    CHECK(parse_datetime("2024-12-31 00:00:01", &t) && t == 1735603201LL);
    CHECK(parse_datetime("2100-03-01 00:00:00", &t) && t == 4107542400LL);  /* 2100 not leap */
    char buffer[24];
    format_datetime(1795177815LL, buffer, sizeof buffer);
    CHECK(strcmp(buffer, "2026-11-20 12:30:15") == 0);
}

static void test_bad_dates(void) {
    printf("invalid dates are rejected\n");
    long long t;
    CHECK(!parse_datetime("2023-02-29 10:00:00", &t));   /* 2023 not leap  */
    CHECK(!parse_datetime("2100-02-29 10:00:00", &t));   /* 2100 not leap  */
    CHECK(parse_datetime("2000-02-29 10:00:00", &t));    /* 2000 IS leap   */
    CHECK(!parse_datetime("2026-13-01 10:00:00", &t));
    CHECK(!parse_datetime("2026-04-31 10:00:00", &t));
    CHECK(!parse_datetime("2026-11-20 24:00:00", &t));
    CHECK(!parse_datetime("2026-11-20 12:60:00", &t));
    CHECK(!parse_datetime("2026-11-20 12:30:60", &t));
    CHECK(!parse_datetime("2026-11-20T12:30:15", &t));
    CHECK(!parse_datetime("2026-11-2 12:30:15", &t));
    CHECK(!parse_datetime("", &t) && !parse_datetime(NULL, &t));
    CHECK(!parse_datetime("1969-12-31 23:59:59", &t));
}

static void test_round_trip(void) {
    printf("days_from_civil / civil_from_days round trip for 1970..2369\n");
    int y = 1970, m = 1, d = 1, bad = 0;
    static const int len[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (long long day = 0; day < 146097; day++) {      /* one full 400-year cycle */
        int yy, mm, dd;
        if (days_from_civil(y, m, d) != day) bad++;
        civil_from_days(day, &yy, &mm, &dd);
        if (yy != y || mm != m || dd != d) bad++;
        /* step the calendar one day forward the slow, obvious way */
        int leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int month_length = (m == 2 && leap) ? 29 : len[m - 1];
        if (++d > month_length) { d = 1; if (++m > 12) { m = 1; y++; } }
    }
    CHECK(bad == 0);
}

static void test_lines(void) {
    printf("parse_line accepts good lines and rejects bad ones\n");
    LoginEvent e;
    CHECK(parse_line("2026-11-20 12:30:15,192.168.1.10,admin,FAILED", &e));
    CHECK(e.timestamp == 1795177815LL && strcmp(e.ip, "192.168.1.10") == 0);
    CHECK(strcmp(e.username, "admin") == 0 && e.success == 0);
    CHECK(parse_line("2026-11-20 12:30:15, 10.0.0.1 ,bob,success\r\n", &e) && e.success == 1);
    CHECK(strcmp(e.ip, "10.0.0.1") == 0);

    const char *bad[] = {
        "2026-11-20 12:30:15,192.168.1.10,admin",                 /* 3 fields      */
        "2026-11-20 12:30:15,192.168.1.10,admin,FAILED,extra",    /* 5 fields      */
        "2026-11-20 12:30:15,192.168.1.300,admin,FAILED",         /* octet > 255   */
        "2026-11-20 12:30:15,192.168.1,admin,FAILED",             /* 3 octets      */
        "2026-11-20 12:30:15,192.168.1.1.5,admin,FAILED",         /* 5 octets      */
        "2026-11-20 12:30:15,abc.def.ghi.jkl,admin,FAILED",
        "2026-11-20 12:30:15,1.2.3.4,,FAILED",                    /* empty user    */
        "2026-11-20 12:30:15,1.2.3.4,bad user,FAILED",            /* space in name */
        "2026-11-20 12:30:15,1.2.3.4,admin,MAYBE",
        "not a date,1.2.3.4,admin,FAILED",
        ",,,",
        "",
        "2026-11-20 12:30:15,1.2.3.4,averyveryveryverylongusernamethatistoolong,FAILED",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(!parse_line(bad[i], &e));
    CHECK(!parse_line(NULL, &e));

    char csv[128];
    parse_line("2026-01-05 03:04:05,8.8.8.8,root,SUCCESS", &e);
    event_to_csv(&e, csv, sizeof csv);
    CHECK(strcmp(csv, "2026-01-05 03:04:05,8.8.8.8,root,SUCCESS") == 0);
}

static void test_text_and_stats(void) {
    printf("parse_text counts good, ignored and malformed lines\n");
    const char *text =
        "# comment line\n"
        "2026-11-20 12:30:15,192.168.1.10,admin,FAILED\r\n"
        "\n"
        "garbage line here\n"
        "2026-11-20 12:30:16,192.168.1.10,root,FAILED\n"
        "2026-11-20 12:30:17,10.1.1.1,alice,SUCCESS";        /* no final newline */
    EventList list;
    ParseStats stats = {0, 0, 0, 0, 0};
    event_list_init(&list);
    CHECK(parse_text(text, &list, &stats) == 3);
    CHECK(list.count == 3 && stats.events_ok == 3);
    CHECK(stats.ignored == 2 && stats.malformed == 1 && stats.first_bad_line == 4);
    CHECK(stats.lines_read == 6);
    CHECK(strcmp(list.items[2].username, "alice") == 0);

    /* a huge line must be counted as malformed, not crash */
    static char huge[3000];
    memset(huge, 'A', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    ParseStats s2 = {0, 0, 0, 0, 0};
    CHECK(parse_text(huge, &list, &s2) == 0 && s2.malformed == 1);

    /* growing past the initial capacity */
    for (int i = 0; i < 1000; i++) event_list_add(&list, &list.items[0]);
    CHECK(list.count == 1003 && list.capacity >= 1003);
    event_list_free(&list);
    CHECK(list.items == NULL && list.count == 0);
}

static void test_file(void) {
    printf("parse_file reads a file and handles a missing one\n");
    const char *path = "test_parser_tmp.csv";
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL);
    if (f == NULL) return;
    fprintf(f, "2026-11-20 12:30:15,1.1.1.1,a,FAILED\r\n2026-11-20 12:30:16,1.1.1.1,b,FAILED\r\nbad\r\n");
    for (int i = 0; i < 700; i++) fputc('x', f);            /* over-long last line */
    fputc('\n', f);
    fclose(f);
    EventList list;
    ParseStats stats = {0, 0, 0, 0, 0};
    event_list_init(&list);
    CHECK(parse_file(path, &list, &stats) == 2);
    CHECK(stats.malformed == 2 && stats.lines_read == 4);
    CHECK(parse_file("does_not_exist.csv", &list, NULL) == -1);
    event_list_free(&list);
    remove(path);
}

int main(void) {
    test_known_dates();
    test_bad_dates();
    test_round_trip();
    test_lines();
    test_text_and_stats();
    test_file();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
