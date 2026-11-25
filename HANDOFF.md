# HANDOFF: Brute-Force Attack Detector (DSA Lab Project)

Read this first if you continue the project in a new session.

## STATUS: all 13 phases done

| Phase | Item | Status |
|---|---|---|
| 1 | Workspace, build.bat, run.bat, run_tests.bat, Makefile | DONE |
| 2 | Circular-array deque | DONE, tested |
| 3 | Hash table, separate chaining | DONE, tested |
| 4 | Max heap + IP-to-index map | DONE, tested |
| 5 | Circular queue (bans), linked list (alerts), stack (Undo, bonus) | DONE, tested |
| 6 | CSV parser, portable date conversion | DONE, tested |
| 7 | Detection engine, scoring, ban logic | DONE, tested |
| 8 | Seeded attack simulator (5 scenarios + mixed) | DONE, tested |
| 9 | Baseline detector, evaluation, benchmarks | DONE, tested |
| 10 | Dashboard (7 pages) | DONE, tested in Chromium on Linux |
| 11 | C HTTP server + JSON API | DONE, tested (curl, browser, ASan stress test) |
| 12 | Integration tests (test_api, test_server, api_smoke.ps1) | DONE (ps1 not run) |
| 13 | README, DETECTION.md, DATA_STRUCTURES.md (complexity + viva Q&A) | DONE |

## Verified vs not verified
* Verified on Linux (GCC 13): 12 test programs, 25,585 checks, 0 failures; no warnings with
  `-std=c11 -Wall -Wextra -pedantic`; clean under AddressSanitizer, UBSan, LeakSanitizer.
  Server stress-tested under ASan. Dashboard driven in headless Chromium, no console errors,
  no horizontal overflow at 390 px width.
* Cross-compiled for Windows with MinGW-w64 (`-Werror`): detector.exe and all 12 tests.
* NOT verified on Windows: running any .exe, build.bat/run.bat/run_tests.bat, api_smoke.ps1,
  Winsock code paths, Edge/Chrome on Windows. First thing on the Windows laptop:
  `.\build.bat`, `.\run_tests.bat`, `.\run.bat`, then the checklist in README.md.

## Bugs found by testing and fixed (useful viva stories)
1. `event_list_add` read its argument after `realloc` (use-after-free if the argument pointed into
   the list). Fix: copy first. Found by ASan in test_parser.
2. server.c kept a POINTER to the end of the HTTP headers while the buffer could still be
   reallocated by a large upload (crash on a 3.3 MB upload), and wrote a '\0' past the data when a
   client disconnected mid-body. Fix: store an OFFSET; reject incomplete bodies. Found by ASan stress test.
3. A wrong printf format in an error branch of main.c (found by -Werror).
4. First evaluation: 1.54 % false alarms (all from a shared office IP) and fast bots mislabelled.
   Fixes: a successful login forgives that username's failures from that IP; a ban without a
   category takes the score component with the most points. Now 0.19 % false alarms, 0 wrongly
   blocked, 100 % correct categories.
5. Dashboard overflowed on narrow windows after resizing (grid `1fr` + canvas; top-5 table without
   a scroll container). Fixed with `minmax(0, 1fr)` and a scroll wrapper.

## Rules that must keep holding
* Backend C11 only, hand-written data structures, no external libraries.
* JavaScript only displays C output (search/filter choose rows; no detection in JS).
* Simulated blocking only; never touch the Windows Firewall; no admin rights.
* Every number shown comes from a real run. Sample data is labelled "sample data".
* Windows-only code behind `#ifdef _WIN32` with a POSIX branch (server.c, platform.c, test_server.c).
* build.bat, run_tests.bat and the Makefile list the same tests and modules: change all three together.

## Possible extensions (not required)
* O(1) manual unblock with a hash table IP -> queue slot.
* Doubly linked list with a tail pointer for O(1) alert trimming.
* IPv6 support in the parser.
