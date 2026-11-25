# Real-Time Brute-Force Attack Detector
### Using multi-window deques and priority queues (Data Structures Engineering Lab)

A defensive, **simulation-only** program that watches login attempts and detects suspicious
activity that a simple "5 failures in 1 minute" rule misses: fast brute-force, low-and-slow
attacks, credential stuffing, and distributed attacks on one username.

* Backend: **C11 only**, every data structure written by hand (deque, hash table, max heap,
  circular queue, linked list, stack).
* The same C program is a tiny web server on **127.0.0.1 only** and serves a dark dashboard
  (HTML, CSS, vanilla JavaScript). The JavaScript never detects anything; it shows what C computed.
* Blocking is **simulated**. Nothing on your computer is changed: no firewall rules, no admin rights.
* No real attacks, no real passwords. All attack traffic comes from a seeded simulator.

---

## Run it on Windows 10/11 (PowerShell)

**1. Install the compiler (once).**
1. Download and install MSYS2 from https://www.msys2.org (keep the default folder `C:\msys64`).
2. Open **"MSYS2 UCRT64"** from the Start menu and run:
   ```
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```
3. Add `C:\msys64\ucrt64\bin` to your PATH: Start, type "environment variables",
   "Edit the system environment variables", Environment Variables, select `Path` (user), Edit, New,
   paste `C:\msys64\ucrt64\bin`, OK.
4. Open a **new** PowerShell window and check: `gcc --version`

**2. Build.** Unzip the project, open PowerShell in the `BruteForceDetector` folder, then:
```powershell
.\build.bat         # builds detector.exe and the 12 test programs; stops on the first error
.\run_tests.bat     # runs all tests; must end with "ALL UNIT TESTS PASSED"
```

**3. Run.**
```powershell
.\run.bat
```
Open the address it prints, normally **http://localhost:8080** (if 8080 is busy it uses 8081,
8082, ... and prints that instead). Keep the window open; press **Ctrl+C** in it to stop.
If Windows shows a firewall question you may click Cancel: the dashboard only uses 127.0.0.1,
which the firewall does not block.

**4. Try it.** Attack simulator page, pick "Fast brute-force", press **Start simulation**, then
watch Overview, Threat intelligence and Blocked IPs update as the C engine detects the attack.

Optional: `.\run.bat --evaluate` prints the baseline-vs-proposed table in the console.
`.\run.bat --make-sample` regenerates `data\sample_auth.log`.

### If the page looks broken or empty
* **Unstyled page, broken logo, huge black shapes:** `index.html` was opened by itself (often by
  double-clicking it inside the ZIP, which extracts only that one file). Extract the whole ZIP,
  run `.\run.bat`, and type `http://localhost:8080` into the address bar.
* **Dark page with "You opened index.html as a file":** same fix; a page opened from disk cannot talk
  to the C program, only a page loaded from `http://localhost:8080` can.
* **"Cannot reach detector.exe":** the `run.bat` window was closed or stopped; start it again.
* **The browser says the site can't be reached:** check the address that `run.bat` printed
  (it may be 8081 if 8080 was busy).

### What to test first
1. `.\run_tests.bat` passes on your laptop.
2. The dashboard opens and the top bar shows "Idle" (not "Offline").
3. Simulate **Fast brute-force**: the attacker IP appears in Blocked IPs within seconds.
4. Simulate **Low-and-slow** at speed 300x: the IP is flagged after roughly 23 simulated minutes (under 5 real seconds at 300x).
5. Press **Unblock** on a blocked IP; it disappears from the list.
6. Settings: change the ban score to 40, save, then **Undo**.
7. Performance analysis: **Run evaluation**; the numbers should match the table below
   (speed numbers will differ, detection numbers should be identical).
8. Attack simulator: **Load sample log**; the page reports 2 malformed lines skipped.
9. With `.\run.bat` running, in a second window:
   `powershell -ExecutionPolicy Bypass -File tests\api_smoke.ps1`

---

## Results (measured, not typed in)

From `detector --evaluate` with default settings. Full method and discussion: `docs/DETECTION.md`.

| Attack type | Multi-window detector | Baseline (5 failures / 60 s) |
|---|---|---|
| Fast brute-force | 100 % (detected in 4 s on average) | 100 % (6 s) |
| Low-and-slow | 100 % (about 23 min) | 0 % |
| Credential stuffing | 100 % (about 2 min) | 0 % |
| Distributed attack | 100 % (about 2 min) | 0 % |
| False alarms on 520 normal IPs | 0.19 % (one shared office IP flagged, never blocked) | 0 % |
| Speed | about 477,000 events/s | about 23.6 million events/s |

These are results on **our own simulated attacks**; real attackers vary more. The baseline is
faster because it does far less work per event.

---

## How it works (short)

For every IP the detector keeps **three deques** of failed-login timestamps: 10 seconds, 10 minutes
and 1 hour. New failures go in at the rear, expired ones leave from the front. Hash tables find
each IP's record and track usernames per IP and IPs per username. A weighted **threat score**
combines the windows, distinct usernames, attacks on a shared target, and recent activity. A **max
heap** ranks IPs by score; at the ban score an IP gets a simulated ban in a **circular queue**, and
alerts go into a **linked list**. A **stack** stores old settings for Undo.

* Detection rules, formula, worked example: `docs/DETECTION.md`
* Every data structure, complexity, viva questions and answers: `docs/DATA_STRUCTURES.md`

### Complexity at a glance

| Structure | Main operations | Time |
|---|---|---|
| Deque (circular array) | push rear / pop front / peek | O(1) amortized / O(1) / O(1) |
| Hash table (chaining, resize at 75 %) | put / get / remove | O(1) average, O(n) worst |
| Max heap + index map | insert or update / extract max / top-k | O(log n) / O(log n) / O(n + k log n) |
| Circular queue | enqueue / dequeue / unblock | O(1) / O(1) / O(n) |
| Linked list (capped at 200) | add newest / get i-th | O(1) + trim / O(i) |
| Stack (20 entries) | push / pop | O(1) |
| One login event, whole pipeline | | O(log n), n = ranked IPs |

---

## Project structure

```
BruteForceDetector/
  backend/
    deque.c/.h           circular-array deque (time windows)
    hashtable.c/.h       hash table with separate chaining
    heap.c/.h            max heap + IP-to-index map (ranking)
    circular_queue.c/.h  simulated bans in expiry order
    linkedlist.c/.h      recent alerts, newest first
    stack.c/.h           settings history for Undo
    settings.h           the adjustable values
    parser.c/.h          CSV parser, portable date conversion, event array
    detector.c/.h        detection engine: windows, score, categories, bans
    simulator.c/.h       seeded attack generator, merge sort, ground truth
    baseline.c/.h        single-rule detector for comparison
    evaluation.c/.h      accuracy and speed comparison
    platform.c/.h        steady clock (QueryPerformanceCounter on Windows)
    json.c/.h            string builder, JSON escaping, form decoding
    app.c/.h             simulation clock, replay, data for the dashboard
    api.c/.h             JSON API (/api/...)
    server.c/.h          HTTP server: Winsock on Windows, POSIX sockets elsewhere
    main.c               entry point and main loop
  frontend/              index.html, css/style.css, js/app.js, assets/
  data/sample_auth.log   SAMPLE DATA (simulated), includes 2 deliberately broken lines
  tests/                 12 C test programs + api_smoke.ps1
  docs/                  DETECTION.md, DATA_STRUCTURES.md, WINDOWS_UPDATE.md
  build.bat run.bat run_tests.bat Makefile HANDOFF.md
```

**Log format** (one event per line; blank lines and `#` comments are ignored; bad lines are
skipped and counted):
```
2026-11-20 12:30:15,192.168.1.10,admin,FAILED
```

### The main loop (no threads)
```
forever:
    wait up to 100 ms for one browser request (select) and answer it
    advance the simulation clock by elapsed real time x speed
    feed every event whose time has come to the detector
```

### HTTP API
| Request | Effect |
|---|---|
| `GET /api/state` | everything the dashboard shows (JSON) |
| `POST /api/start`, `/pause`, `/reset`, `/clear` | control the replay; clear the live table |
| `POST /api/speed` `speed=60` | simulated seconds per real second |
| `POST /api/simulate` `type=fast&attempts=60&ips=1&username=admin&users=25&seed=7` | type: normal, fast, slow, stuffing, distributed, mixed |
| `POST /api/load_sample` | replay `data/sample_auth.log` |
| `POST /api/upload?name=x.csv` (body = CSV text, max 4 MB) | replay an uploaded log |
| `POST /api/settings` `short=5&medium=8&long=15&score=60&ban=300` (+ `w_short` ... weights) | change settings (old ones go on the Undo stack) |
| `POST /api/settings/undo`, `/api/settings/defaults` | undo / restore defaults |
| `POST /api/unblock` `ip=1.2.3.4` | manual unblock (simulation) |
| `POST /api/evaluate` `seeds=5&events=300000` | run the comparison |

---

## Tests

| Program | Checks | What it covers |
|---|---|---|
| test_deque | 130 | push/pop, wrap-around, growth, window helper |
| test_hashtable | 5038 | insert/search/delete, collisions, resize with 5000 keys |
| test_heap | 38 | ordering, updates up and down, remove, top-k, 20,000 random operations |
| test_circular_queue | 20056 | full/empty, wrap-around, order rule, lazy deletion, batches, random model test |
| test_linkedlist | 69 | newest first, cap, ids, edge cases |
| test_stack | 16 | LIFO, full stack drops the oldest |
| test_parser | 51 | dates (400-year round trip, leap years), valid/invalid lines, files |
| test_detector | 64 | each attack type, ban expiry, shortened duration, unblock, decay |
| test_simulator | 40 | reproducibility, sorting, labels, CSV round trip, detector on each scenario |
| test_evaluation | 21 | baseline rule; evaluation counts are consistent and reproducible |
| test_api | 46 | every API route, validation, settings/undo, upload, evaluation |
| test_server | 16 | real HTTP over a 127.0.0.1 socket: files, API, broken requests |

**25,585 checks in total, 0 failures** on Linux (GCC 13), with no compiler warnings under
`-std=c11 -Wall -Wextra -pedantic`, and no errors or leaks under AddressSanitizer, UBSan and
LeakSanitizer. The running server was also stress-tested under AddressSanitizer (every route,
3.3 MB upload, cut-off and oversized requests, 300 random request bodies); this found two real
memory bugs, which are fixed and covered by `test_server`.

---

## Honest status: what is verified and what is not

| Item | Status |
|---|---|
| All C code compiles and all 12 tests pass on Linux, clean under sanitizers | **verified** |
| Server, API and dashboard work end to end in a real browser (Chromium) on Linux | **verified** |
| All C code cross-compiles to Windows .exe with MinGW-w64, no warnings | **verified** |
| Running `detector.exe` and the tests **on Windows** | **not verified** (no Windows machine was available) |
| `build.bat`, `run.bat`, `run_tests.bat` on Windows | **not verified** (written carefully, never executed) |
| `tests/api_smoke.ps1` | **not verified** (no PowerShell was available) |
| Winsock-specific code paths (WSAStartup, closesocket, QueryPerformanceCounter) | compiled, **not executed** |
| Dashboard in Edge/Chrome on Windows | **not verified** (tested in Chromium on Linux) |

If something fails on Windows, run `.\build.bat` and `.\run_tests.bat` and note the first error.
