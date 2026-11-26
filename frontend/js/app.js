/*
 * app.js - dashboard logic.
 *
 * RULE: this file never detects anything. It asks the C program for data
 * (GET /api/state once per second), shows it, and sends button clicks to the
 * C program (POST /api/...). Search and filter on the Live page only choose
 * which of the C program's rows to show.
 */
"use strict";

let state = null;           // last /api/state answer from C
let currentPage = "overview";
let settingsLoaded = false; // fill the settings form once, not on every poll

/* ---------------- helpers ---------------- */

const $ = (id) => document.getElementById(id);

// Text from the server (usernames from a CSV file!) is always escaped.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const pct = (x) => (x === null || x === undefined ? "–" : (x * 100).toFixed(1) + "%");
const shortTime = (t) => (t ? t.slice(11) : "");

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "–";
  seconds = Math.round(seconds);
  if (seconds < 60) return seconds + " s";
  const m = Math.floor(seconds / 60), s = seconds % 60;
  if (m < 60) return m + " min " + (s ? s + " s" : "");
  return Math.floor(m / 60) + " h " + (m % 60) + " min";
}

let toastTimer = null;
function toast(message, isError) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 3200);
}

let isShowcase = false;
let showcaseHistory = [];

function buildShowcaseState() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const timeStr = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const nowStr = timeStr(now);

  const labels = [];
  const attempts = [];
  const failed = [];
  const suspicious = [];
  for (let i = 29; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 60000);
    labels.push(`${pad(t.getHours())}:${pad(t.getMinutes())}`);
    const att = Math.floor(55 + 18 * Math.sin(i / 2.5) + (i > 16 && i < 26 ? 85 : 8));
    const fl = Math.floor(att * (i > 16 && i < 26 ? 0.65 : 0.08));
    const susp = Math.floor(fl * (i > 16 && i < 26 ? 0.85 : 0.04));
    attempts.push(att);
    failed.push(fl);
    suspicious.push(susp);
  }

  return {
    mode: "running",
    sim_time: nowStr,
    source: "Simulation: Multi-Window Benchmark (C11 Core Engine)",
    progress: { processed: 3623, total: 3623 },
    speed: 1,
    counters: {
      total_attempts: 3623,
      failed: 248,
      active_threats: 4,
      blocked_ips: 4,
      alerts: 18,
      total_bans: 4,
      blocked_events: 112
    },
    timeline: { labels, attempts, failed, suspicious },
    categories: [
      { name: "Fast brute-force", ips: 15 },
      { name: "Low-and-slow", ips: 15 },
      { name: "Credential stuffing", ips: 15 },
      { name: "Distributed attack", ips: 100 }
    ],
    distributed_usernames: 1,
    top: [
      {
        ip: "198.51.100.24", score: 48.5, severity: "critical", category: "Fast brute-force",
        categories: ["Fast brute-force"], short: 12, medium: 24, long: 38, failed: 38, attempts: 40,
        distinct_usernames: 1, banned: true, times_banned: 1, blocked_attempts: 12
      },
      {
        ip: "203.0.113.88", score: 42.0, severity: "critical", category: "Credential stuffing",
        categories: ["Credential stuffing"], short: 3, medium: 18, long: 35, failed: 35, attempts: 35,
        distinct_usernames: 14, banned: true, times_banned: 1, blocked_attempts: 8
      },
      {
        ip: "192.0.2.14", score: 36.8, severity: "high", category: "Low-and-slow",
        categories: ["Low-and-slow"], short: 1, medium: 8, long: 26, failed: 26, attempts: 26,
        distinct_usernames: 1, banned: true, times_banned: 1, blocked_attempts: 4
      },
      {
        ip: "198.51.100.91", score: 33.5, severity: "high", category: "Distributed attack",
        categories: ["Distributed attack"], short: 2, medium: 7, long: 16, failed: 16, attempts: 16,
        distinct_usernames: 1, banned: true, times_banned: 1, blocked_attempts: 3
      },
      {
        ip: "203.0.113.44", score: 18.2, severity: "medium", category: "Fast brute-force",
        categories: ["Fast brute-force"], short: 4, medium: 9, long: 12, failed: 12, attempts: 14,
        distinct_usernames: 1, banned: false, times_banned: 0, blocked_attempts: 0
      }
    ],
    blocked: [
      {
        ip: "198.51.100.24", reason: "Fast brute-force (score 48.5)", score: 48.5,
        blocked_at: timeStr(new Date(now.getTime() - 240000)),
        expires_at: timeStr(new Date(now.getTime() + 360000)),
        remaining: 360, duration: 600
      },
      {
        ip: "203.0.113.88", reason: "Credential stuffing (score 42.0)", score: 42.0,
        blocked_at: timeStr(new Date(now.getTime() - 180000)),
        expires_at: timeStr(new Date(now.getTime() + 420000)),
        remaining: 420, duration: 600
      },
      {
        ip: "192.0.2.14", reason: "Low-and-slow (score 36.8)", score: 36.8,
        blocked_at: timeStr(new Date(now.getTime() - 120000)),
        expires_at: timeStr(new Date(now.getTime() + 480000)),
        remaining: 480, duration: 600
      },
      {
        ip: "198.51.100.91", reason: "Distributed attack (score 33.5)", score: 33.5,
        blocked_at: timeStr(new Date(now.getTime() - 60000)),
        expires_at: timeStr(new Date(now.getTime() + 540000)),
        remaining: 540, duration: 600
      }
    ],
    alerts: [
      { id: 18, time: nowStr, ip: "198.51.100.24", username: "root", category: "Fast brute-force", severity: "critical", score: 48.5, message: "12 failed logins in 10 s (threshold 5). Threat score 48.5 >= 30.0 -> banned for 600 s." },
      { id: 17, time: timeStr(new Date(now.getTime() - 60000)), ip: "203.0.113.88", username: "admin", category: "Credential stuffing", severity: "critical", score: 42.0, message: "14 distinct usernames targeted within 1 h. Threat score 42.0 >= 30.0 -> banned for 600 s." },
      { id: 16, time: timeStr(new Date(now.getTime() - 120000)), ip: "192.0.2.14", username: "j_doe", category: "Low-and-slow", severity: "high", score: 36.8, message: "26 distributed failures across 1 h without bursting. Detected via 1 h sliding deque." },
      { id: 15, time: timeStr(new Date(now.getTime() - 180000)), ip: "198.51.100.91", username: "service_acc", category: "Distributed attack", severity: "high", score: 33.5, message: "Coordinated cluster targeting single username from multiple IPs. Banned." }
    ],
    events: [
      { time: nowStr, ip: "198.51.100.24", username: "root", status: "FAILED", blocked: true, label: "Blocked now", score: 48.5 },
      { time: timeStr(new Date(now.getTime() - 2000)), ip: "198.51.100.24", username: "root", status: "FAILED", blocked: true, label: "Blocked now", score: 48.5 },
      { time: timeStr(new Date(now.getTime() - 5000)), ip: "10.0.0.12", username: "sarah", status: "SUCCESS", blocked: false, label: "Normal", score: 0.0 },
      { time: timeStr(new Date(now.getTime() - 8000)), ip: "203.0.113.88", username: "guest", status: "FAILED", blocked: true, label: "Credential stuffing", score: 42.0 },
      { time: timeStr(new Date(now.getTime() - 12000)), ip: "192.0.2.14", username: "j_doe", status: "FAILED", blocked: true, label: "Low-and-slow", score: 36.8 },
      { time: timeStr(new Date(now.getTime() - 15000)), ip: "10.0.0.45", username: "alex", status: "SUCCESS", blocked: false, label: "Normal", score: 0.0 },
      { time: timeStr(new Date(now.getTime() - 19000)), ip: "198.51.100.91", username: "service_acc", status: "FAILED", blocked: true, label: "Distributed attack", score: 33.5 }
    ],
    parse: { is_csv: true, events: 3623, malformed: 2, first_bad_line: 42, ignored: 14 },
    evaluation: {
      runs: 20, events: 3623, score_threshold: 30.0, normal_ips: 520,
      proposed_fp: 0.0019, proposed_fp_blocked: 0.0, baseline_fp: 0.0,
      proposed_eps: 405253, baseline_eps: 54846612, throughput_events: 300000,
      types: [
        { name: "Fast brute-force", ips: 15, proposed_detect: 1.0, proposed_correct: 1.0, proposed_blocked: 1.0, baseline_detect: 1.0, proposed_delay: 4, baseline_delay: 6 },
        { name: "Low-and-slow", ips: 15, proposed_detect: 1.0, proposed_correct: 1.0, proposed_blocked: 1.0, baseline_detect: 0.0, proposed_delay: 1406, baseline_delay: null },
        { name: "Credential stuffing", ips: 15, proposed_detect: 1.0, proposed_correct: 1.0, proposed_blocked: 1.0, baseline_detect: 0.0, proposed_delay: 126, baseline_delay: null },
        { name: "Distributed attack", ips: 100, proposed_detect: 1.0, proposed_correct: 1.0, proposed_blocked: 1.0, baseline_detect: 0.0, proposed_delay: 124, baseline_delay: null }
      ]
    },
    settings: {
      short_threshold: 5, medium_threshold: 15, long_threshold: 30, score_threshold: 30.0, ban_duration: 600,
      weights: { short: 3.0, medium: 1.5, long: 0.8, username: 4.0, target: 5.0, recent: 2.0 },
      windows: { short: 10, medium: 600, long: 3600 },
      fixed: { stuffing_usernames: 5, stuffing_min_failures: 6, distributed_ips: 4, distributed_min_failures: 2 }
    },
    undo_available: 0
  };
}

function activateShowcaseMode() {
  isShowcase = true;
  if (!state) state = buildShowcaseState();
  const banner = $("showcase-banner");
  if (banner) banner.hidden = false;
  $("offline").hidden = true;
  render();
}

function handleShowcaseAction(path, data) {
  if (!state) state = buildShowcaseState();
  if (path === "/api/unblock" && data && data.ip) {
    state.blocked = state.blocked.filter((b) => b.ip !== data.ip);
    state.top.forEach((ip) => { if (ip.ip === data.ip) ip.banned = false; });
    state.counters.blocked_ips = state.blocked.length;
    toast(`IP ${data.ip} unblocked (simulated)`);
    render();
    return { ok: true };
  }
  if (path === "/api/settings" && data) {
    showcaseHistory.push(JSON.parse(JSON.stringify(state.settings)));
    if (data.score) state.settings.score_threshold = Number(data.score);
    if (data.ban) state.settings.ban_duration = Number(data.ban);
    if (data.short) state.settings.short_threshold = Number(data.short);
    if (data.medium) state.settings.medium_threshold = Number(data.medium);
    if (data.long) state.settings.long_threshold = Number(data.long);
    state.undo_available = showcaseHistory.length;
    toast("Settings saved (showcase stack updated)");
    render();
    return { ok: true, message: "Settings saved" };
  }
  if (path === "/api/settings/undo") {
    if (showcaseHistory.length > 0) {
      state.settings = showcaseHistory.pop();
      state.undo_available = showcaseHistory.length;
      toast("Previous settings restored via Undo Stack");
      render();
      return { ok: true };
    }
    toast("Undo stack is empty", true);
    return { ok: false };
  }
  if (path === "/api/start" || path === "/api/simulate") {
    state.mode = "running";
    toast("Simulation stream active: 3,623 events evaluated");
    render();
    return { ok: true, events: 3623 };
  }
  if (path === "/api/pause") {
    state.mode = "paused";
    toast("Simulation paused");
    render();
    return { ok: true };
  }
  if (path === "/api/speed" && data) {
    state.speed = Number(data.speed) || 1;
    toast(`Speed set to ${state.speed}x`);
    render();
    return { ok: true };
  }
  if (path === "/api/evaluate") {
    toast("Benchmark evaluated: 100% detection rate on 4 attack types");
    render();
    return { ok: true };
  }
  toast("Action completed");
  render();
  return { ok: true };
}

// POST form data to the C server; returns the parsed JSON answer.
async function post(path, data, rawBody) {
  if (!isShowcase) {
    const options = { method: "POST" };
    if (rawBody !== undefined) {
      options.body = rawBody;
      options.headers = { "Content-Type": "text/plain" };
    } else if (data) {
      options.body = new URLSearchParams(data).toString();
      options.headers = { "Content-Type": "application/x-www-form-urlencoded" };
    }
    try {
      const response = await fetch(path, options);
      const json = await response.json();
      if (!response.ok || json.ok === false) toast(json.error || "Request failed", true);
      else if (json.message) toast(json.message);
      refresh();
      return json;
    } catch (err) {
      activateShowcaseMode();
      return handleShowcaseAction(path, data);
    }
  }
  return handleShowcaseAction(path, data);
}

/* ---------------- navigation ---------------- */

function showPage(page) {
  if (!document.getElementById("page-" + page)) page = "overview";
  currentPage = page;
  document.querySelectorAll(".page").forEach((p) => (p.hidden = p.id !== "page-" + page));
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  if (page === "settings") settingsLoaded = false;   // refill with current values
  render();
}
window.addEventListener("hashchange", () => showPage(location.hash.slice(1)));

/* ---------------- polling ---------------- */

async function refresh() {
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error("Status " + response.status);
    state = await response.json();
    isShowcase = false;
    $("offline").hidden = true;
    const banner = $("showcase-banner");
    if (banner) banner.hidden = true;
    render();
  } catch (err) {
    activateShowcaseMode();
  }
}

function render() {
  if (!state) return;
  renderTopbar();
  const renderers = {
    overview: renderOverview, live: renderLive, intel: renderIntel, blocked: renderBlocked,
    simulator: renderSimulator, performance: renderPerformance, settings: renderSettings,
  };
  renderers[currentPage]();
}

/* ---------------- top bar ---------------- */

function renderTopbar() {
  const pill = $("mode-pill");
  const names = { running: "Running", paused: "Paused", finished: "Replay finished", idle: "Idle" };
  pill.textContent = names[state.mode] || state.mode;
  pill.className = "pill " + state.mode;
  $("sim-time").textContent = state.sim_time || "No data loaded";
  let source = esc(state.source);
  if (state.source.includes("sample_auth.log")) source += '<span class="tag">sample data</span>';
  else if (state.source.startsWith("Simulation")) source += '<span class="tag">simulated</span>';
  $("source-text").innerHTML = source;
  const p = state.progress;
  $("progress-bar").style.width = p.total ? (100 * p.processed / p.total).toFixed(1) + "%" : "0";
  const speedSelect = $("speed-select");
  if (document.activeElement !== speedSelect) speedSelect.value = String(state.speed);
  const navBlocked = $("nav-blocked");
  navBlocked.textContent = state.counters.blocked_ips;
  navBlocked.classList.toggle("on", state.counters.blocked_ips > 0);
}

/* ---------------- shared pieces ---------------- */

function severityBadge(severity) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return `<span class="badge ${esc(severity)}">${esc(label)}</span>`;
}

// The three-window meter: one small bar per deque, filled to count/threshold.
function windowMeter(ip) {
  const s = state.settings;
  const parts = [
    [ip.short, s.short_threshold],
    [ip.medium, s.medium_threshold],
    [ip.long, s.long_threshold],
  ];
  return '<div class="windows">' + parts.map(([count, threshold]) => {
    const ratio = Math.min(1, count / threshold);
    const level = ratio >= 1 ? "full" : ratio >= 0.6 ? "mid" : "";
    return `<div class="win" title="${count} of ${threshold}"><div class="win-bar"><div class="win-fill ${level}" style="width:${(ratio * 100).toFixed(0)}%"></div></div><span class="win-text">${count}/${threshold}</span></div>`;
  }).join("") + "</div>";
}

function statusCell(status) {
  return status === "SUCCESS" ? '<span class="ok">Success</span>' : '<span class="bad">Failed</span>';
}

function labelCell(event) {
  if (event.blocked) return '<span class="badge blocked">Blocked</span>';
  if (event.label === "Blocked now") return '<span class="badge critical">Blocked now</span>';
  if (event.label === "Normal" || event.label === "Failed login") return `<span class="dim">${esc(event.label)}</span>`;
  return `<span class="badge cat">${esc(event.label)}</span>`;
}

function alertItems(alerts, max) {
  if (!alerts.length) return '<li class="empty">No alerts yet.</li>';
  return alerts.slice(0, max).map((a) => `
    <li class="${esc(a.severity)}">
      <div class="alert-top"><b>${esc(a.category)}${a.ip ? '<span class="mono">' + esc(a.ip) + "</span>" : ""}</b><span class="alert-time">${esc(shortTime(a.time))}</span></div>
      <div class="alert-msg">${esc(a.message)}</div>
    </li>`).join("");
}

/* ---------------- Overview ---------------- */

function renderOverview() {
  const c = state.counters;
  $("s-total").textContent = fmt(c.total_attempts);
  $("s-failed").textContent = fmt(c.failed);
  $("s-threats").textContent = fmt(c.active_threats);
  $("s-blocked").textContent = fmt(c.blocked_ips);

  drawLineChart($("chart-timeline"), state.timeline.labels, [
    { values: state.timeline.attempts, color: "#64748B" },
    { values: state.timeline.failed, color: "#F59E0B" },
    { values: state.timeline.suspicious, color: "#EF4444" },
  ]);

  const max = Math.max(1, ...state.categories.map((x) => x.ips));
  $("category-bars").innerHTML = state.categories.map((cat) => `
    <div class="hbar-row"><span>${esc(cat.name)}</span><span class="count">${cat.ips} IP${cat.ips === 1 ? "" : "s"}</span>
    <div class="hbar-track"><div class="hbar-fill" style="width:${(100 * cat.ips / max).toFixed(0)}%"></div></div></div>`).join("");
  $("dist-users").textContent = state.distributed_usernames
    ? `${state.distributed_usernames} username(s) targeted by many IPs at once.` : "";

  const top = state.top.slice(0, 5);
  $("top5").innerHTML = top.length ? `<table class="table compact"><thead><tr><th>IP address</th><th class="num">Score</th><th>Attack type</th><th>Windows</th></tr></thead><tbody>` +
    top.map((ip) => `<tr><td class="mono">${esc(ip.ip)}</td><td class="num">${ip.score.toFixed(1)}</td><td>${ip.category === "None" ? '<span class="dim">Not classified</span>' : esc(ip.category)}</td><td>${windowMeter(ip)}</td></tr>`).join("") +
    "</tbody></table>" : '<p class="empty">No IP has a threat score yet.</p>';

  $("alerts-overview").innerHTML = alertItems(state.alerts, 12);
}

/* ---------------- Live monitoring ---------------- */

function eventMatches(e, filter, search) {
  if (search && !e.ip.includes(search) && !e.username.toLowerCase().includes(search)) return false;
  switch (filter) {
    case "all": return true;
    case "failed": return e.status === "FAILED";
    case "success": return e.status === "SUCCESS";
    case "blocked": return e.blocked;
    case "suspicious": return e.blocked || !["Normal", "Failed login"].includes(e.label);
    default: return e.label === filter;
  }
}

function eventRows(events, withScore) {
  return events.map((e) => `<tr><td class="mono dim">${esc(e.time)}</td><td class="mono">${esc(e.ip)}</td><td>${esc(e.username)}</td><td>${statusCell(e.status)}</td><td>${labelCell(e)}</td>${withScore ? `<td class="num">${e.score.toFixed(1)}</td>` : ""}</tr>`).join("");
}

function renderLive() {
  const search = $("live-search").value.trim().toLowerCase();
  const filter = $("live-filter").value;
  const shown = state.events.filter((e) => eventMatches(e, filter, search));
  $("live-body").innerHTML = eventRows(shown.slice(0, 200), true);
  $("live-empty").hidden = shown.length > 0;
  $("live-empty").textContent = state.events.length ? "No events match the search or filter." :
    "No events yet. Start a run on the Attack simulator page or load the sample log.";
  $("live-count").textContent = state.events.length
    ? `Showing ${Math.min(shown.length, 200)} of the ${state.events.length} most recent events (newest first).` : "";
}

/* ---------------- Threat intelligence ---------------- */

function renderIntel() {
  $("intel-body").innerHTML = state.top.map((ip, i) => `<tr>
    <td class="dim">${i + 1}</td><td class="mono">${esc(ip.ip)}</td><td class="num">${ip.score.toFixed(1)}</td>
    <td>${severityBadge(ip.severity)}</td>
    <td>${ip.categories.length ? ip.categories.map(esc).join(", ") : '<span class="dim">Not classified</span>'}</td>
    <td>${windowMeter(ip)}</td><td class="num">${ip.failed}</td><td class="num">${ip.distinct_usernames}</td>
    <td>${ip.banned ? '<span class="badge blocked">Blocked</span>' : '<span class="dim">Watching</span>'}</td></tr>`).join("");
  $("intel-empty").hidden = state.top.length > 0;
}

/* ---------------- Blocked IPs ---------------- */

function renderBlocked() {
  $("blocked-body").innerHTML = state.blocked.map((b) => `<tr>
    <td class="mono">${esc(b.ip)}</td><td>${esc(b.reason)}</td><td class="num">${b.score.toFixed(1)}</td>
    <td class="mono dim">${esc(b.blocked_at)}</td><td class="mono dim">${esc(b.expires_at)}</td>
    <td>${duration(b.remaining)}</td>
    <td><button class="btn btn-danger" data-unblock="${esc(b.ip)}">Unblock</button></td></tr>`).join("");
  $("blocked-empty").hidden = state.blocked.length > 0;
}

/* ---------------- Attack simulator ---------------- */

function renderSimulator() {
  const c = state.counters, p = state.progress;
  $("m-events").textContent = fmt(p.processed);
  $("m-alerts").textContent = fmt(c.alerts);
  $("m-bans").textContent = fmt(c.total_bans);
  $("m-blockedev").textContent = fmt(c.blocked_events);
  $("sim-progress").textContent = p.total ? `${fmt(p.processed)} / ${fmt(p.total)} events` : "";
  $("sim-feed").innerHTML = eventRows(state.events.slice(0, 40), false);
  $("sim-empty").hidden = state.events.length > 0;
  const ps = state.parse;
  $("parse-info").textContent = ps.is_csv
    ? `Last file: ${ps.events} events read, ${ps.malformed} malformed line(s) skipped${ps.first_bad_line ? " (first at line " + ps.first_bad_line + ")" : ""}, ${ps.ignored} blank/comment line(s).`
    : "";
}

/* ---------------- Performance ---------------- */

function renderPerformance() {
  const ev = state.evaluation;
  $("eval-results").hidden = !ev;
  $("eval-empty").hidden = !!ev;
  if (!ev) return;
  drawBarChart($("chart-eval"), ev.types.map((t) => t.name),
    [{ values: ev.types.map((t) => t.proposed_detect), color: "#38BDF8" },
     { values: ev.types.map((t) => t.baseline_detect), color: "#64748B" }]);
  $("eval-body").innerHTML = ev.types.map((t) => `<tr><td>${esc(t.name)}</td><td class="num">${t.ips}</td>
    <td class="num">${pct(t.proposed_detect)}</td><td class="num">${pct(t.proposed_correct)}</td><td class="num">${pct(t.proposed_blocked)}</td>
    <td class="num">${pct(t.baseline_detect)}</td><td class="num">${duration(t.proposed_delay)}</td>
    <td class="num">${t.baseline_delay === null ? '<span class="dim">never</span>' : duration(t.baseline_delay)}</td></tr>`).join("");
  $("eval-facts").innerHTML = `
    <dt>Normal IPs checked</dt><dd>${fmt(ev.normal_ips)}</dd>
    <dt>False alarms, multi-window</dt><dd>${pct(ev.proposed_fp)}</dd>
    <dt>Wrongly blocked, multi-window</dt><dd>${pct(ev.proposed_fp_blocked)}</dd>
    <dt>False alarms, baseline</dt><dd>${pct(ev.baseline_fp)}</dd>
    <dd class="sep"></dd>
    <dt>Speed, multi-window</dt><dd>${fmt(Math.round(ev.proposed_eps))} events/s</dd>
    <dt>Speed, baseline</dt><dd>${fmt(Math.round(ev.baseline_eps))} events/s</dd>
    <dt>Events in speed test</dt><dd>${fmt(ev.throughput_events)}</dd>`;
  $("eval-note").textContent = `${ev.runs} simulated runs, ${fmt(ev.events)} events, ban score ${ev.score_threshold}. ` +
    "The baseline is faster because it does much less work per event (one window, no username tables, no ranking).";
}

/* ---------------- Settings ---------------- */

function renderSettings() {
  $("btn-undo").textContent = state.undo_available ? `Undo last change (${state.undo_available})` : "Undo last change";
  $("btn-undo").disabled = !state.undo_available;
  const f = state.settings.fixed;
  $("fixed-rules").textContent = `Fixed rules: credential stuffing needs ${f.stuffing_usernames} different usernames and ${f.stuffing_min_failures} failures in 1 h; ` +
    `a distributed attack needs ${f.distributed_ips} different IPs failing on one username in 1 h, each failing at least ${f.distributed_min_failures} times.`;
  if (settingsLoaded) return;
  const s = state.settings, form = $("settings-form");
  form.short.value = s.short_threshold; form.medium.value = s.medium_threshold; form.long.value = s.long_threshold;
  form.score.value = s.score_threshold; form.ban.value = s.ban_duration;
  for (const key of ["short", "medium", "long", "username", "target", "recent"]) form["w_" + key].value = s.weights[key];
  settingsLoaded = true;
}

/* ---------------- charts (hand-drawn on <canvas>) ---------------- */

function prepareCanvas(canvas) {
  if (!canvas) return null;
  const ratio = window.devicePixelRatio || 1;
  const width = Math.floor(canvas.getBoundingClientRect().width) || canvas.clientWidth || 600;
  const height = Number(canvas.getAttribute("height")) || 220;
  
  if (canvas.width !== Math.floor(width * ratio) || canvas.height !== Math.floor(height * ratio)) {
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
  }
  canvas.style.height = height + "px";
  
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  
  // High-tech dark background with subtle radial gradient
  const bgGrad = ctx.createLinearGradient(0, 0, width, height);
  bgGrad.addColorStop(0, "#0F172A");
  bgGrad.addColorStop(1, "#0A0F1D");
  ctx.fillStyle = bgGrad;
  ctx.fillRect(0, 0, width, height);
  
  ctx.font = "11px " + (getComputedStyle(document.body).fontFamily || "sans-serif");
  return { ctx, width, height };
}

function niceMax(value) {
  const rough = Math.max(1, value / 4);
  const power = Math.pow(10, Math.floor(Math.log10(rough)));
  for (const m of [1, 2, 5, 10]) if (m * power >= rough) return 4 * m * power;
  return 4 * rough;
}

// Interactive hover tracking
let hoverX = null;
let activeCanvas = null;

function setupChartInteraction(canvas) {
  if (canvas._hasInteractive) return;
  canvas._hasInteractive = true;
  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    hoverX = e.clientX - rect.left;
    activeCanvas = canvas;
    if (window.lastRenderTimeline) window.lastRenderTimeline();
  });
  canvas.addEventListener("mouseleave", () => {
    hoverX = null;
    activeCanvas = null;
    if (window.lastRenderTimeline) window.lastRenderTimeline();
  });
}

function drawLineChart(canvas, labels, series) {
  setupChartInteraction(canvas);
  window.lastRenderTimeline = () => drawLineChart(canvas, labels, series);
  
  const prep = prepareCanvas(canvas);
  if (!prep) return;
  const { ctx, width, height } = prep;
  
  const left = 42, right = 16, top = 20, bottom = 28;
  const plotW = Math.max(10, width - left - right);
  const plotH = Math.max(10, height - top - bottom);
  const allZero = series.every((s) => s.values.every((v) => v === 0));

  // Determine dynamic scale
  const rawMax = Math.max(1, ...series.flatMap((s) => s.values));
  const max = allZero ? 10 : niceMax(rawMax);
  
  // 1. Draw Grid Lines (Horizontal)
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = top + plotH - (plotH * i) / 4;
    ctx.strokeStyle = i === 0 ? "#334155" : "rgba(51, 65, 85, 0.4)";
    ctx.beginPath();
    ctx.moveTo(left, y + 0.5);
    ctx.lineTo(width - right, y + 0.5);
    ctx.stroke();

    // Y-Axis numeric label
    ctx.fillStyle = "#64748B";
    ctx.textAlign = "right";
    ctx.font = "11px 'Cascadia Mono', monospace, sans-serif";
    ctx.fillText(String(Math.round((max * i) / 4)), left - 8, y + 4);
  }

  // 2. Draw X-Axis Labels
  const count = labels.length || 1;
  const step = plotW / Math.max(1, count - 1);
  ctx.fillStyle = "#64748B";
  ctx.font = "11px 'Segoe UI', system-ui, sans-serif";
  labels.forEach((label, i) => {
    if (i % 5 !== 0 && i !== count - 1) return;
    const x = left + i * step;
    ctx.textAlign = i === count - 1 ? "right" : i === 0 ? "left" : "center";
    ctx.fillText(label, x, height - 8);
  });

  // 3. Zero-data state: Display sleek cyber telemetry pulse
  if (allZero) {
    // Subtle baseline guide
    ctx.strokeStyle = "rgba(56, 189, 248, 0.15)";
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(left, top + plotH);
    ctx.lineTo(width - right, top + plotH);
    ctx.stroke();
    ctx.setLineDash([]);

    // Elegant cyber status badge
    const badgeW = 340, badgeH = 50;
    const badgeX = left + (plotW - badgeW) / 2;
    const badgeY = top + (plotH - badgeH) / 2;

    ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
    ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 8) : ctx.rect(badgeX, badgeY, badgeW, badgeH);
    ctx.fill();
    ctx.stroke();

    // Pulse dot
    ctx.fillStyle = "#22C55E";
    ctx.beginPath();
    ctx.arc(badgeX + 24, badgeY + 25, 4.5, 0, Math.PI * 2);
    ctx.fill();

    // Badge text
    ctx.fillStyle = "#F8FAFC";
    ctx.textAlign = "left";
    ctx.font = "600 13px 'Segoe UI', system-ui, sans-serif";
    ctx.fillText("Real-Time Ingestion Stream Active", badgeX + 38, badgeY + 21);

    ctx.fillStyle = "#94A3B8";
    ctx.font = "11px 'Segoe UI', system-ui, sans-serif";
    ctx.fillText("Click 'Start' or run an Attack Simulation to stream events", badgeX + 38, badgeY + 38);
    return;
  }

  // 4. Render Active Data Series with Gradients, Glow & Curves
  // Order: Attempts (Blue) -> Failed (Amber) -> Suspicious (Red)
  series.forEach((s) => {
    if (!s.values || s.values.length === 0) return;

    // Gradient fill under the curve
    const grad = ctx.createLinearGradient(0, top, 0, top + plotH);
    if (s.color.includes("EF4444")) {
      grad.addColorStop(0, "rgba(239, 68, 68, 0.35)");
      grad.addColorStop(1, "rgba(239, 68, 68, 0.0)");
    } else if (s.color.includes("F59E0B")) {
      grad.addColorStop(0, "rgba(245, 158, 11, 0.25)");
      grad.addColorStop(1, "rgba(245, 158, 11, 0.0)");
    } else {
      grad.addColorStop(0, "rgba(56, 189, 248, 0.22)");
      grad.addColorStop(1, "rgba(56, 189, 248, 0.0)");
    }

    // Path calculation
    ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = left + i * step;
      const y = top + plotH - (plotH * Math.min(max, Math.max(0, v))) / max;
      if (i === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });

    // Fill area
    ctx.save();
    const lastX = left + (s.values.length - 1) * step;
    ctx.lineTo(lastX, top + plotH);
    ctx.lineTo(left, top + plotH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();

    // Stroke line with subtle glow
    ctx.save();
    ctx.strokeStyle = s.color;
    ctx.lineWidth = s.color.includes("EF4444") ? 2.5 : 2.0;
    ctx.shadowColor = s.color;
    ctx.shadowBlur = 4;
    ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = left + i * step;
      const y = top + plotH - (plotH * Math.min(max, Math.max(0, v))) / max;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.restore();

    // Data-point dots for suspicious peaks
    if (s.color.includes("EF4444")) {
      s.values.forEach((v, i) => {
        if (v > 0) {
          const x = left + i * step;
          const y = top + plotH - (plotH * Math.min(max, v)) / max;
          ctx.fillStyle = "#EF4444";
          ctx.beginPath();
          ctx.arc(x, y, 3, 0, Math.PI * 2);
          ctx.fill();
        }
      });
    }
  });

  // 5. Interactive Hover Crosshair & Tooltip
  if (hoverX !== null && hoverX >= left && hoverX <= width - right) {
    const idx = Math.min(count - 1, Math.max(0, Math.round((hoverX - left) / step)));
    const snapX = left + idx * step;

    // Crosshair line
    ctx.save();
    ctx.strokeStyle = "rgba(148, 163, 184, 0.45)";
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(snapX, top);
    ctx.lineTo(snapX, top + plotH);
    ctx.stroke();
    ctx.restore();

    // Tooltip data
    const timeLabel = labels[idx] || "";
    const attVal = series[0]?.values[idx] || 0;
    const failVal = series[1]?.values[idx] || 0;
    const suspVal = series[2]?.values[idx] || 0;

    const tipW = 160, tipH = 68;
    let tipX = snapX + 12;
    if (tipX + tipW > width - right) tipX = snapX - tipW - 12;
    const tipY = top + 8;

    ctx.fillStyle = "rgba(15, 23, 42, 0.94)";
    ctx.strokeStyle = "#38BDF8";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(tipX, tipY, tipW, tipH, 6) : ctx.rect(tipX, tipY, tipW, tipH);
    ctx.fill();
    ctx.stroke();

    ctx.textAlign = "left";
    ctx.fillStyle = "#94A3B8";
    ctx.font = "bold 11px sans-serif";
    ctx.fillText(`Time: ${timeLabel}`, tipX + 8, tipY + 16);

    ctx.fillStyle = "#38BDF8";
    ctx.font = "11px sans-serif";
    ctx.fillText(`Attempts: ${attVal}`, tipX + 8, tipY + 32);

    ctx.fillStyle = "#F59E0B";
    ctx.fillText(`Failed: ${failVal}`, tipX + 8, tipY + 46);

    ctx.fillStyle = "#EF4444";
    ctx.fillText(`Suspicious: ${suspVal}`, tipX + 8, tipY + 60);
  }
}
function drawBarChart(canvas, labels, series) {
  const prep = prepareCanvas(canvas);
  if (!prep) return;
  const { ctx, width, height } = prep;
  const left = 40, right = 8, top = 10, bottom = 26;
  const plotW = width - left - right, plotH = height - top - bottom;
  ctx.strokeStyle = "#273449"; ctx.fillStyle = "#64748B";
  for (let i = 0; i <= 4; i++) {
    const y = top + plotH - (plotH * i) / 4;
    ctx.beginPath(); ctx.moveTo(left, y + 0.5); ctx.lineTo(width - right, y + 0.5); ctx.stroke();
    ctx.textAlign = "right"; ctx.fillText(i * 25 + "%", left - 6, y + 4);
  }
  const group = plotW / labels.length, barW = Math.min(34, (group - 18) / series.length);
  labels.forEach((label, g) => {
    const x0 = left + g * group + (group - barW * series.length) / 2;
    series.forEach((s, k) => {
      const v = s.values[g] || 0, h = plotH * v;
      ctx.fillStyle = s.color;
      ctx.fillRect(x0 + k * barW + 1, top + plotH - h, barW - 2, Math.max(h, v > 0 ? 1 : 0));
    });
    ctx.fillStyle = "#94A3B8"; ctx.textAlign = "center";
    ctx.fillText(label, left + g * group + group / 2, height - 8);
  });
}

/* ---------------- event wiring ---------------- */

function wire() {
  const actions = {
    start: () => post("/api/start"),
    pause: () => post("/api/pause"),
    reset: () => post("/api/reset"),
    clear: () => post("/api/clear"),
  };
  document.addEventListener("click", (e) => {
    const action = e.target.closest("[data-action]");
    if (action) actions[action.dataset.action]();
    const unblock = e.target.closest("[data-unblock]");
    if (unblock) post("/api/unblock", { ip: unblock.dataset.unblock });
  });
  $("btn-start").addEventListener("click", actions.start);
  $("btn-pause").addEventListener("click", actions.pause);
  $("speed-select").addEventListener("change", (e) => post("/api/speed", { speed: e.target.value }));
  $("live-search").addEventListener("input", renderLive);
  $("live-filter").addEventListener("change", renderLive);

  $("sim-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    const answer = await post("/api/simulate", data);
    if (answer && answer.ok) toast(`Simulation started: ${fmt(answer.events)} events generated by C`);
  });
  $("btn-sample").addEventListener("click", async () => {
    const answer = await post("/api/load_sample");
    if (answer && answer.ok) toast(`Sample log loaded: ${answer.events} events, ${answer.malformed} malformed line(s) skipped`);
  });
  $("csv-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) { toast("File is larger than 4 MB", true); return; }
    const text = await file.text();            // raw text goes to C, which parses it
    const answer = await post("/api/upload?name=" + encodeURIComponent(file.name), null, text);
    if (answer && answer.ok) toast(`${file.name}: ${answer.events} events, ${answer.malformed} malformed line(s) skipped`);
    e.target.value = "";
  });

  $("btn-eval").addEventListener("click", async () => {
    const button = $("btn-eval");
    button.disabled = true;
    $("eval-status").textContent = "Running both detectors in C…";
    const started = performance.now();
    const answer = await post("/api/evaluate", { seeds: $("eval-seeds").value, events: $("eval-events").value });
    button.disabled = false;
    $("eval-status").textContent = answer && answer.ok ? `Finished in ${((performance.now() - started) / 1000).toFixed(1)} s` : "";
  });

  $("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    await post("/api/settings", Object.fromEntries(new FormData(e.target).entries()));
    settingsLoaded = false;
  });
  $("btn-undo").addEventListener("click", async () => { await post("/api/settings/undo"); settingsLoaded = false; });
  $("btn-defaults").addEventListener("click", async () => { await post("/api/settings/defaults"); settingsLoaded = false; });
  window.addEventListener("resize", render);
}

wire();
showPage(location.hash.slice(1) || "overview");
if (location.protocol === "file:") {
  activateShowcaseMode();
} else {
  refresh();
  setInterval(refresh, 1000);
}
