/*
 * settings.h - the values the user can change from the Settings page.
 *
 * Kept in its own small header because three modules need it:
 * the detector (uses the values), the stack (stores old copies for Undo)
 * and the server (reads new values from the dashboard).
 */
#ifndef SETTINGS_H
#define SETTINGS_H

typedef struct {
    /* --- the five values shown on the Settings page --- */
    int    short_threshold;     /* failures in the 10 s window  -> fast brute-force */
    int    medium_threshold;    /* failures in the 10 min window -> low-and-slow    */
    int    long_threshold;      /* failures in the 1 h window    -> low-and-slow    */
    double score_threshold;     /* threat score at which an IP is (simulated) banned */
    int    ban_duration;        /* length of a simulated ban, in seconds            */

    /* --- weights of the threat score (see docs/DETECTION.md) --- */
    double weight_short;        /* points per failure in the 10 s window            */
    double weight_medium;       /* points per failure in the 10 min window          */
    double weight_long;         /* points per failure in the 1 h window             */
    double weight_username;     /* points per extra distinct username tried         */
    double weight_target;       /* points per failure on a username under attack    */
    double weight_recent;       /* bonus if the IP failed within the last 10 s      */
} Settings;

/* Fills s with the default values. Defined in detector.c. */
void settings_set_defaults(Settings *s);

/* Clamps every value into a safe range (e.g. thresholds >= 1).
 * Returns 1 if nothing had to be changed, 0 if something was clamped. */
int settings_validate(Settings *s);

#endif
