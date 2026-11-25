/*
 * main.c - entry point of detector.exe
 *
 *   detector.exe                 start the dashboard server (default port 8080)
 *   detector.exe --port 9000     use another first port
 *   detector.exe --evaluate      print the baseline vs proposed table and exit
 *   detector.exe --make-sample   regenerate data/sample_auth.log and exit
 *
 * Main loop (single thread, no extra threads):
 *     forever:
 *         wait up to 100 ms for a browser request and answer it
 *         advance the simulation clock and feed due events to the detector
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "app.h"
#include "server.h"
#include "platform.h"
#include "evaluation.h"

static volatile sig_atomic_t stop_requested = 0;

/* Ctrl+C sets a flag; the main loop sees it within 100 ms and exits cleanly
 * (memory freed, sockets closed). signal() is standard C and works in a
 * Windows console too. */
static void on_ctrl_c(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;
    fclose(f);
    return 1;
}

/* Works whether started from the project folder or from backend/. */
static void find_folders(char *frontend, char *data, int size) {
    if (file_exists("frontend/index.html")) {
        copy_text(frontend, size, "frontend");
        copy_text(data, size, "data");
    } else {
        copy_text(frontend, size, "../frontend");
        copy_text(data, size, "../data");
    }
}

static int make_sample(const char *data_dir) {
    SimConfig c;
    EventList events;
    GroundTruth truth;
    char path[300];
    sim_config_defaults(&c);
    c.attack_type = SIM_MIXED;
    c.attempts = 40;
    c.attacker_ips = 10;
    event_list_init(&events);
    ground_truth_init(&truth);
    int count = sim_generate(&c, &events, &truth);
    snprintf(path, sizeof path, "%s/sample_auth.log", data_dir);
    int ok = count > 0 && sim_write_csv(&events, path,
        "SAMPLE DATA - simulated login events (seed 2026, mixed scenario). Format: time,ip,username,status");
    if (ok) {
        /* Two broken lines on purpose, to show that the parser skips and counts them. */
        FILE *file = fopen(path, "a");
        ok = file != NULL;
        if (file != NULL) {
            fprintf(file, "# The next two lines are deliberately malformed: the parser skips and counts them.\n");
            fprintf(file, "2026-11-20 25:00:00,10.0.0.99,employee99,FAILED\n");
            fprintf(file, "2026-11-20 00:50:00,10.0.0.300,employee99,FAILED\n");
            ok = fclose(file) == 0;
        }
    }
    event_list_free(&events);
    ground_truth_free(&truth);
    if (ok) printf("Wrote %d simulated events to %s\n", count, path);
    else    printf("Could not write %s\n", path);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    int first_port = 8080;
    char frontend_dir[256], data_dir[256];
    find_folders(frontend_dir, data_dir, (int)sizeof frontend_dir);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            first_port = atoi(argv[++i]);
            if (first_port < 1024 || first_port > 65000) first_port = 8080;
        } else if (strcmp(argv[i], "--evaluate") == 0) {
            Settings s;
            EvalResults r;
            settings_set_defaults(&s);
            printf("Running baseline vs proposed evaluation on simulated data...\n");
            if (!evaluation_run(&s, 1000, 5, 300000, &r)) { printf("Evaluation failed.\n"); return 1; }
            evaluation_print(&r);
            return 0;
        } else if (strcmp(argv[i], "--make-sample") == 0) {
            return make_sample(data_dir);
        } else {
            printf("Usage: detector [--port N] [--evaluate] [--make-sample]\n");
            return 1;
        }
    }

    App app;
    if (!app_init(&app, data_dir)) { printf("Out of memory.\n"); return 1; }
    if (!server_startup()) { printf("Could not start the network library (WSAStartup failed).\n"); return 1; }
    int port = 0;
    if (!server_open(first_port, 20, &port)) {
        printf("Could not open any port from %d to %d. Close other programs or use --port.\n",
               first_port, first_port + 19);
        server_cleanup();
        app_free(&app);
        return 1;
    }
    if (!file_exists("frontend/index.html") && !file_exists("../frontend/index.html"))
        printf("WARNING: frontend/index.html not found. Start detector from the project folder.\n");

    printf("\n  Brute-Force Attack Detector (simulation only - nothing is really blocked)\n");
    printf("  Dashboard:  http://localhost:%d\n", port);
    if (port != first_port) printf("  (port %d was busy, so %d is used)\n", first_port, port);
    printf("  Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    signal(SIGINT, on_ctrl_c);
    app.last_wall = platform_seconds();
    while (!stop_requested) {
        server_poll(&app, frontend_dir, 100);
        app_step(&app, platform_seconds());
    }

    printf("Stopping...\n");
    server_close();
    server_cleanup();
    app_free(&app);
    return 0;
}
