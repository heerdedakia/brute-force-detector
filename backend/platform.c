/*
 * platform.c - steady clock for timing benchmarks and pacing the simulation.
 */
#ifdef _WIN32
#include <windows.h>

double platform_seconds(void) {
    /* QueryPerformanceFrequency: how many "ticks" the high-resolution
     * counter makes per second (fixed at boot).
     * QueryPerformanceCounter: the current tick count.
     * ticks / ticks_per_second = seconds. */
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
}

#else
/* clock_gettime is POSIX, not plain C11, so we ask for POSIX definitions
 * before including <time.h>. */
#define _POSIX_C_SOURCE 199309L
#include <time.h>

double platform_seconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}
#endif
