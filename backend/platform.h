/*
 * platform.h - the ONLY place (besides server.c) with operating-system code.
 * Everything here has a Windows version and a POSIX (Linux/macOS) version,
 * chosen at compile time with #ifdef _WIN32.
 */
#ifndef PLATFORM_H
#define PLATFORM_H

/* Seconds since some fixed moment, from a steady clock that never jumps
 * backwards. Only differences between two calls are meaningful.
 * Windows: QueryPerformanceCounter / QueryPerformanceFrequency.
 * POSIX:   clock_gettime(CLOCK_MONOTONIC). */
double platform_seconds(void);

#endif
