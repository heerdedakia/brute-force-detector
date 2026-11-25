# How the detector decides

This file explains the detection engine (`backend/detector.c`), every threshold it uses, and how
the comparison with the baseline was measured. All numbers in the examples were produced by running
the program; none were typed in by hand.

## 1. The idea in one paragraph

A traditional detector has one rule, for example "block an IP after 5 failures in 1 minute".
An attacker who waits 90 seconds between guesses never trips it. Our detector keeps **three sliding
windows per IP** at the same time (10 seconds, 10 minutes, 1 hour), remembers **which usernames**
each IP tried and **which IPs** attacked each username, and combines all of this into one
**threat score**. IPs are ranked by score in a max heap, high scores lead to a simulated ban in a
circular queue, and alerts go into a linked list.

## 2. What happens for every login event

`detector_process(detector, event, result)` does these steps, in this order:

1. **Clock.** The simulation clock becomes the event's timestamp. (An event older than the clock is
   treated as happening "now" and counted in `out_of_order_events`, because the deques need time order.)
2. **Expire bans.** Bans whose end time has passed are taken off the front of the circular queue.
3. **Find the IP record** in the hash table (create it if new).
4. **Banned IP?** Then the attempt is stopped (simulated): it is counted as a blocked attempt and
   does *not* touch the windows. Label: `Blocked`.
5. **Failed login?** Its timestamp is pushed onto the rear of all three deques; the username's
   failure count for this IP goes up; this IP is recorded in the username's table of failing IPs.
   **Successful login?** That username is removed from the IP's "failed usernames" table, and the IP
   from that username's failing-IP table ("forgiveness", see section 5).
6. **Slide the windows:** timestamps that are too old are popped from the front of each deque.
7. **Recompute the score** and update the IP's place in the max heap (`heap_set`, O(log n)).
8. **After a failure only:** check the four category rules, then ban if `score >= ban score`.
9. **Tick:** every 5 simulated seconds, quiet IPs are rescored so their scores decay.

## 3. The threat score

```
score = weight_short    x failures in the last 10 s
      + weight_medium   x failures in the last 10 min
      + weight_long     x failures in the last 1 h
      + weight_username x (distinct usernames this IP failed on - 1)
      + weight_target   x failures on a username that is under distributed attack
      + weight_recent   x (1 if the IP's last failure was less than 10 s ago, else 0)
```

| Weight | Default | Why this size |
|---|---|---|
| `weight_short` | 8 | A burst is the strongest sign of a bot. |
| `weight_medium` | 3 | Each failure counts in all three windows, so the totals add up. |
| `weight_long` | 1.5 | Slow attacks build up points over an hour. |
| `weight_username` | 8 | Real people retry *their own* username; bots try many. |
| `weight_target` | 10 | Joining an attack on a username others are attacking is very suspicious. |
| `weight_recent` | 5 | Small bonus while an IP is active right now. |

A failure is in all three windows at first, so one fresh failure is worth 8 + 3 + 1.5 + 5 = **17.5 points**.

**Decay.** Nothing is multiplied down. Old timestamps simply fall out of the front of each deque,
so the score shrinks by itself: after 10 s the short part is gone, after 10 min the medium part,
after 1 h everything. When the 1 h window becomes empty, the IP's username table and categories
are cleared (a new "activity period" starts). The heap only contains IPs with a score above 0,
and the tick only revisits those.

All six weights can be changed on the Settings page (section "Score weights").

## 4. The four categories

Wording is cautious on purpose: an alert says "suspicious" or "possible", never "malicious".

| Category | Rule (default values) | Adjustable? |
|---|---|---|
| Fast brute-force | failures in 10 s >= **5** | yes, "Fast brute-force threshold" |
| Low-and-slow | (failures in 10 min >= **8** OR in 1 h >= **15**) AND the 10 s window is below its threshold | yes, both thresholds |
| Credential stuffing | distinct failed usernames >= **5** AND failures in 1 h >= **5** | fixed (`STUFFING_*` in detector.h) |
| Distributed attack | a username has failures from >= **5** different IPs within 1 h; every IP that failed on it >= **2** times is flagged | fixed (`DISTRIBUTED_*`) |

Two more rules:

* **Ban score:** after a failed login, `score >= 60` (default) starts a simulated ban of
  **300 s** (default). Both are adjustable.
* **Category at ban time:** sometimes the score crosses 60 *before* any rule above fires. Example:
  a fast bot that also rotates usernames reaches 71 points after 4 tries, while the fast rule needs 5.
  Then the category becomes the part of the score formula that contributed the most points
  (`flag_dominant_category`). Without this, fast bots were labelled "High threat score" instead of
  "Fast brute-force" (measured: only 6.7 % correctly categorised before the fix, 100 % after).

## 5. Why "a successful login forgives typos"

The first evaluation showed 1.54 % false alarms, and **every one** came from the simulated office
router (8 staff members sharing one public IP). Their ordinary typos on 8 different usernames looked
exactly like credential stuffing. The fix: when a username logs in successfully from an IP, that
IP has proven it knows the password, so its earlier failures *for that username* stop counting
towards "many usernames" and towards the distributed-attack table. The time windows are not changed.
Credential-stuffing bots rarely log in successfully, so they are still caught.
After the fix: 0.19 % false alarms and **no** normal IP wrongly blocked.

## 6. Worked example (real output)

`6.6.6.6` is a fast bot trying a different common username every 2 s. `10.0.0.5` is a person who
makes two typos and then logs in. Default settings. Times are seconds from the start.

```
t=0    6.6.6.6   admin  FAILED  short=1 medium=1 long=1 users=1 score=17.5  Failed login
t=2    6.6.6.6   root   FAILED  short=2 medium=2 long=2 users=2 score=38.0  Failed login
t=4    6.6.6.6   admin  FAILED  short=3 medium=3 long=3 users=2 score=50.5  Failed login
t=6    6.6.6.6   test   FAILED  short=4 medium=4 long=4 users=3 score=71.0  Blocked now
t=8    6.6.6.6   admin  FAILED  (stopped, windows unchanged)    score=71.0  Blocked
t=10   6.6.6.6   root   FAILED  (stopped)                       score=71.0  Blocked
t=15   10.0.0.5  alice  FAILED  short=1 medium=1 long=1 users=1 score=17.5  Failed login
t=21   10.0.0.5  alice  FAILED  short=2 medium=2 long=2 users=1 score=30.0  Failed login
t=27   10.0.0.5  alice  SUCCESS short=1 medium=2 long=2 users=0 score=22.0  Normal
```

Check the arithmetic for t=6: 8x4 + 3x4 + 1.5x4 + 8x(3-1) + 0 + 5 = 32 + 12 + 6 + 16 + 5 = **71**.
For t=27: the short window lost the failure from t=15 (older than 10 s); the success removed
"alice" from the usernames table; the last failure (t=21) is 6 s ago, so the recent bonus applies:
8x1 + 3x2 + 1.5x2 + 5 = **22**.

Alerts produced (newest first): `#3 Unblocked` (the ban expired at t=306), `#2 Blocked` (300 s,
score 71.0, Fast brute-force), `#1 Fast brute-force: 4 failures in 10 s`.

## 7. Bans and the circular queue

* Every ban uses the **same** duration, so the ban that started first ends first, and expiry is
  "dequeue from the front while expired": O(1) per ban.
* `cq_enqueue` **refuses** an entry that would end before the entry at the rear (`CQ_OUT_OF_ORDER`),
  so the queue can never become unsorted.
* **Changing the ban duration** applies to new bans only. If it is made *shorter*, a new ban could
  end before an older one. To keep the order, the new ban is extended to end together with the
  newest older ban: it is never shortened, and nothing expires out of order. (Test:
  `test_shorter_duration_keeps_order` in `tests/test_detector.c`.)
* **Manual unblock** marks the queue entry inactive (lazy deletion); it is skipped when it reaches
  the front. Unblocking also clears that IP's windows, so it gets a fresh start.
* Expiry uses the **simulation clock**, never the wall clock, so every run can be repeated exactly.

## 8. How the comparison was measured (`backend/evaluation.c`)

**Accuracy.** For each attack type and each of 5 seeds, the simulator generates one stream: normal
background traffic (25 users with their own IP plus one shared office IP with 8 users) and the
attack. Both detectors read exactly the same events. Only afterwards are the ground-truth labels
(kept in a separate array the detectors never see) used to count results per IP:

* *Detected* (proposed) = the IP got any category alert or a ban.
  *Detected* (baseline) = the IP was banned (the baseline can do nothing else).
* *Right category* = the proposed detector gave the matching category.
* *False alarm rate* = normal IPs detected / normal IPs.

Attack sizes: fast 3 IPs x 40 tries, low-and-slow 3 x 25, stuffing 3 x 30, distributed 20 x 5.

**Speed.** A mixed scenario with 150 normal users is repeated (shifted in time) to 300,000 events,
and each detector processes them once, timed with `platform_seconds()` (QueryPerformanceCounter on
Windows, a monotonic clock on Linux).

**Results** (`detector --evaluate`, default settings, measured on the Linux build machine with `-O2`;
speed will be different on your laptop, the detection numbers will be identical because the
simulator is seeded):

| Attack type | Attacker IPs | Proposed: detected | Right category | Blocked | Baseline: detected |
|---|---|---|---|---|---|
| Fast brute-force | 15 | 100 % | 100 % | 100 % | 100 % |
| Low-and-slow | 15 | 100 % | 100 % | 100 % | 0 % |
| Credential stuffing | 15 | 100 % | 100 % | 100 % | 0 % |
| Distributed attack | 100 | 100 % | 100 % | 100 % | 0 % |

| Measure | Proposed | Baseline |
|---|---|---|
| False alarms on 520 normal IPs | 0.19 % (1 IP flagged, 0 blocked) | 0 % |
| Mean time to detect: fast | 4 s | 6 s |
| low-and-slow / stuffing / distributed | 1406 s / 126 s / 124 s | never |
| Speed (300,000 events) | about 477,000 events/s | about 23,600,000 events/s |

**Reading these results honestly**

* The 100 % values are for *our own simulated attacks*, whose shapes we designed. Real attackers vary
  more. The point of the comparison is the *difference*: the single-window rule cannot see three of
  the four attack types at all.
* The one false alarm is the shared office IP being flagged "low-and-slow" (8 failures in 10 min from
  8 people). It was not blocked. Shared IPs are a real weakness of IP-based detection.
* Low-and-slow detection takes about 23 minutes; that is the price of not banning people for a
  handful of spread-out typos.
* The baseline is about 50 times faster because it does much less per event. Profiling (gprof) showed
  our time goes into hash-table lookups and rescoring the ~30 IPs that currently have a score. Even
  so, ~477,000 events per second is far more than a login system produces.

## 9. Limitations (say these in the viva before someone else does)

* Simulation only: no real network traffic, no real authentication logs required, no real blocking.
* IPv4 addresses only (the parser rejects other formats and counts them as malformed).
* IP-based: an attacker with thousands of IPs, each trying once, would look like normal users.
* Weights and thresholds were chosen by hand and checked on simulated data, not learned from real attacks.
* The ban queue has a fixed capacity (4096); if it were ever full, new bans are counted in
  `bans_dropped` instead of being applied.
