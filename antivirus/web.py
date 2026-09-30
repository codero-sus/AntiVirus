"""Dependency-free web console (stdlib ``http.server`` only).

    python3 -m antivirus web --port 8420

Serves a single-page dashboard plus a small JSON API:

    GET  /                     the web UI (dashboard)
    GET  /api/health           engine status + version
    POST /api/scan             start a scan job {"target", "action", …}
    GET  /api/jobs             all jobs (summary)
    GET  /api/jobs/<id>        job progress, and the full result when done
    GET  /api/quarantine       quarantined items
    POST /api/quarantine/restore   {"id"}
    POST /api/quarantine/purge     {"id"}
    GET  /api/signatures       signature list
    POST /api/signatures       add a signature
    POST /api/signatures/remove    {"id"}
    GET  /api/verify           ?target=&baseline= – fast integrity check
    GET  /api/stats            engine statistics (sigs/cache/quarantine)
    POST /api/rescue/build     build the rescue kit + ISO image
    GET  /api/rescue           last rescue build (404 until one exists)
    GET  /api/kill             kill registry (key/IV entries)
    POST /api/kill/revive      {"id"} – restore a killed file's bytes
    POST /api/kill/purge       {"id"} – destroy a killed file + entry

Scans run in background threads (jobs) so the UI can poll live progress.
This is a *local* tool: there is no authentication – bind it to an
interface you trust.
"""
from __future__ import annotations

import copy
import json
import threading
import time
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote, urlsplit

from . import __version__
from .config import Config
from .kill import KillRegistry
from .quarantine import Quarantine
from .scanner import ScanResult, Scanner
from .signatures import Signature, SignatureDB, VALID_SEVERITIES
from .utils import parse_since

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AntiVirus Web Console</title>
<style>
:root{
  --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#e6edf3;
  --muted:#8b949e; --accent:#2f81f7; --green:#3fb950; --yellow:#d29922;
  --orange:#db6d28; --red:#f85149;
}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;align-items:center;gap:10px;padding:14px 20px;border-bottom:1px solid var(--border);background:var(--panel)}
header h1{font-size:16px;margin:0}
header .ver{color:var(--muted);font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block}
main{display:grid;grid-template-columns:1.6fr 1fr;gap:14px;padding:14px;max-width:1400px;margin:0 auto}
@media(max-width:980px){main{grid-template-columns:1fr}}
section{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
form.scan{display:grid;grid-template-columns:1fr 140px 130px;gap:8px}
input,select{background:#0d1117;color:var(--text);border:1px solid var(--border);border-radius:6px;padding:8px 10px;font-size:13px;width:100%}
label.opt{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);width:auto}
button{background:var(--accent);border:0;border-radius:6px;color:#fff;padding:8px 16px;font-size:13px;cursor:pointer;width:auto}
button:hover{filter:brightness(1.12)}
button.small{padding:3px 10px;font-size:12px}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
button.danger{background:var(--red)}
.progress{height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin:10px 0 4px}
.progress>div{height:100%;width:0%;background:var(--accent);transition:width .4s}
.muted{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{color:var(--muted);text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid var(--border)}
td{padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-word}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700}
.critical{background:#f8514933;color:var(--red)}
.high{background:#db6d2833;color:var(--orange)}
.medium{background:#d2992233;color:var(--yellow)}
.low{background:#3fb95033;color:var(--green)}
.info{background:#8b949e33;color:var(--muted)}
.summary{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.summary .card{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:8px 14px;min-width:90px}
.summary .num{font-size:20px;font-weight:700}
.empty{color:var(--muted);padding:8px 0}
.joblist{list-style:none;margin:0;padding:0;font-size:12.5px}
.joblist li{padding:5px 8px;border-bottom:1px solid #21262d;cursor:pointer}
.joblist li:hover{background:#1c2129}
.joblist li.active{background:#1f2937}
pre{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto;font-size:12px;max-height:280px}
footer{text-align:center;color:var(--muted);font-size:12px;padding:10px 0 18px}
footer a{color:var(--accent)}
.live{color:var(--accent)}
</style>
</head>
<body>
<header>
  <span class="dot" id="engine-dot"></span>
  <h1>AntiVirus Web Console</h1>
  <span class="ver" id="ver"></span>
  <span style="flex:1"></span>
  <span class="muted" id="clock"></span>
</header>
<main>
  <div>
    <section>
      <h2>New scan</h2>
      <form class="scan" id="scan-form">
        <input id="target" placeholder="Target file or directory" value="." required>
        <select id="action">
          <option value="detect">detect</option>
          <option value="quarantine">quarantine</option>
          <option value="kill">kill (in place)</option>
          <option value="delete">delete</option>
        </select>
        <input id="since" placeholder="since (e.g. 2h) – empty = all">
        <div style="display:flex;gap:14px;align-items:center;grid-column:1/-1">
          <label class="opt"><input type="checkbox" id="fast" style="width:auto"> fast (hash+pattern only)</label>
          <label class="opt"><input type="checkbox" id="no-archives" style="width:auto"> skip archives</label>
          <button type="submit">Scan</button>
        </div>
        <div style="display:flex;gap:6px;align-items:center;grid-column:1/-1">
          <label class="opt" style="flex:0 0 auto">integrity baseline:</label>
          <select id="baseline" style="width:260px">
            <option value="">(off)</option>
          </select>
          <button type="button" class="ghost small" onclick="newBaseline()">new from target</button>
          <button type="button" class="ghost small" onclick="verifyBaseline()">verify (fast)</button>
          <span class="muted">full scan compares against the manifest · verify only re-hashes (no signature scan)</span>
        </div>
      </form>
      <div id="job-status" class="muted" style="display:none">
        <div class="progress"><div id="progress-bar"></div></div>
        <span id="progress-text"></span>
      </div>
    </section>
    <section style="margin-top:14px">
      <h2>Results <span class="muted" id="result-target"></span> <span class="muted live" id="live-flag"></span></h2>
      <div class="summary" id="summary"></div>
      <input id="filter" placeholder="filter findings (name / file / kind / detail)…" style="margin-bottom:8px">
      <table id="findings" style="display:none">
        <thead><tr><th>Severity</th><th>Finding</th><th>Kind</th><th>File</th></tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty" id="clean-msg" style="display:none">No threats found.</div>
    </section>
    <section style="margin-top:14px">
      <h2>Quick file check</h2>
      <div style="display:flex;gap:6px">
        <input id="qpath" placeholder="path to a single file (e.g. samples/behavior/suspicious.exe)">
        <button type="button" class="ghost" onclick="quickScan()">inspect</button>
      </div>
      <pre id="qout" style="display:none"></pre>
    </section>
  </div>
  <div>
    <section>
      <h2>Jobs</h2>
      <ul class="joblist" id="jobs"></ul>
    </section>
    <section style="margin-top:14px">
      <h2>Quarantine <button class="ghost small" style="float:right" onclick="loadQuarantine()">refresh</button></h2>
      <table id="qtable" style="display:none">
        <thead><tr><th>ID</th><th>File</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty" id="q-empty">Quarantine is empty.</div>
    </section>
    <section style="margin-top:14px">
      <h2>Signatures <button class="ghost small" style="float:right" onclick="loadSigs()">refresh</button></h2>
      <table id="sigtable" style="display:none">
        <thead><tr><th>ID</th><th>Severity</th><th>Name</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
      <form id="sig-form" style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:6px">
        <input id="sig-id" placeholder="id (e.g. AV-MY-001)">
        <input id="sig-name" placeholder="name">
        <select id="sig-sev">
          <option>low</option><option selected>medium</option><option>high</option><option>critical</option>
        </select>
        <input id="sig-value" placeholder="pattern (regex) or hash hex">
        <div style="display:flex;gap:12px;align-items:center">
          <label class="opt"><input type="radio" name="sigkind" value="pattern" checked style="width:auto">pattern</label>
          <label class="opt"><input type="radio" name="sigkind" value="sha256" style="width:auto">sha256</label>
          <label class="opt"><input type="radio" name="sigkind" value="md5" style="width:auto">md5</label>
          <button type="submit" class="ghost">add</button>
        </div>
      </form>
    </section>
    <section style="margin-top:14px">
      <h2>Report history</h2>
      <div id="reports" class="muted">…</div>
    </section>
    <section style="margin-top:14px">
      <h2>Engine stats <button class="ghost small" style="float:right" onclick="loadStats()">refresh</button></h2>
      <div id="stats" class="muted">…</div>
    </section>
    <section style="margin-top:14px">
      <h2>Rescue disk <button class="ghost small" style="float:right" onclick="rescueBuild()">build</button></h2>
      <div id="rescue" class="muted">…</div>
      <p class="muted" style="margin-top:8px">Self-contained kit + ISO image: copy to a USB stick, boot any live system (or mount the ISO), then scan the infected volume — threats are quarantined to the rescue media, never into the scanned disk.</p>
    </section>
    <section style="margin-top:14px">
      <h2>Killed in place <button class="ghost small" style="float:right" onclick="loadKill()">refresh</button></h2>
      <div id="kill" class="muted">…</div>
      <p class="muted" style="margin-top:8px">The <b>kill</b> action obfuscates a threat's bytes right where it sits (key + IV stored in the AntiVirus registry) — the file is inert but <b>revivable</b>. Revive restores the exact original bytes; purge destroys both.</p>
    </section>
  </div>
</main>
<footer id="footer"></footer>
<script>
const $ = id => document.getElementById(id);
async function api(path, body, method) {
  const opt = {method: method || (body ? "POST" : "GET"), headers: {}};
  if (body) { opt.body = JSON.stringify(body); opt.headers["Content-Type"] = "application/json"; }
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch (e) {}
  return {ok: r.ok, status: r.status, data};
}
let currentJob = null, pollTimer = null, lastFindings = [];

function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
function sevClass(s) { return ["critical","high","medium","low","info"].includes(s) ? s : "info"; }
function fmtMiB(n) { return (n / 1048576).toFixed(1); }

async function init() {
  const h = await api("/api/health");
  $("ver").textContent = "v" + (h.data.version || "?");
  if (!h.ok) $("engine-dot").style.background = "var(--red)";
  $("footer").innerHTML = "AntiVirus Web Console · " + (h.data.version || "") +
    ' · <a href="/api/docs">API documentation</a>';
  loadJobs(); loadQuarantine(); loadSigs(); loadBaselines(); loadReports();
  loadStats(); loadRescue(); loadKill();
  setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString(); }, 1000);
  $("filter").addEventListener("input", renderFindings);
}

/* ------------------------------------------------------------- scan flow */
$("scan-form").addEventListener("submit", async e => {
  e.preventDefault();
  const body = {target: $("target").value.trim() || ".", action: $("action").value,
                fast: $("fast").checked, no_archives: $("no-archives").checked,
                baseline: $("baseline").value};
  const since = $("since").value.trim();
  if (since) body.since = since;
  const r = await api("/api/scan", body);
  if (!r.ok) { alert("Scan failed: " + (r.data.error || r.status)); return; }
  currentJob = r.data.job;
  lastFindings = [];
  renderFindings();
  startPolling();
});

async function newBaseline() {
  const target = $("target").value.trim() || ".";
  const r = await api("/api/baselines", {target: target});
  if (!r.ok) { alert("Baseline failed: " + (r.data.error || r.status)); return; }
  loadBaselines();
  $("baseline").value = r.data.id;
}
async function loadBaselines() {
  const r = await api("/api/baselines");
  if (!r.ok) return;
  const sel = $("baseline");
  const current = sel.value;
  sel.innerHTML = '<option value="">(off)</option>';
  for (const b of r.data.baselines) {
    const o = document.createElement("option");
    o.value = b.id; o.textContent = b.id;
    sel.appendChild(o);
  }
  if (current) sel.value = current;
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  $("job-status").style.display = "block";
  $("progress-bar").style.width = "8%";
  $("live-flag").textContent = "";
  pollTimer = setInterval(pollJob, 1000);
  pollJob();
}
async function pollJob() {
  if (!currentJob) return;
  const r = await api("/api/jobs/" + currentJob.id);
  if (!r.ok) { stopPolling(); return; }
  const j = r.data.job;
  $("progress-text").textContent = j.target + " — " + j.files_scanned +
    " file(s), " + fmtMiB(j.bytes_scanned) + " MiB, " +
    j.findings + " finding(s)" + (j.baseline ? " [vs baseline]" : "");
  if (j.status === "running") {
    $("progress-bar").style.width = "40%";
    $("live-flag").textContent = "(live)";
    lastFindings = r.data.findings_preview || [];
    renderFindings();
    loadJobs();
  } else {
    stopPolling();
    $("progress-bar").style.width = "100%";
    $("live-flag").textContent = "";
    if (j.status === "error") alert("Scan error: " + j.error);
    if (r.data.result) showResult(r.data.result);
    loadJobs(); loadQuarantine(); loadReports(); loadStats();
  }
}
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

function showResult(d, live) {
  $("result-target").textContent = " — " + d.target;
  lastFindings = d.findings;
  $("summary").innerHTML =
    '<div class="card"><div class="num">' + d.files_scanned + '</div><div class="muted">files</div></div>' +
    '<div class="card"><div class="num">' + lastFindings.length + '</div><div class="muted">threats</div></div>' +
    '<div class="card"><div class="num">' + (d.files_cached || 0) + '</div><div class="muted">cached</div></div>' +
    '<div class="card"><div class="num">' + (d.elapsed_seconds != null ? d.elapsed_seconds : "…") + 's</div><div class="muted">duration</div></div>';
  renderFindings();
}

function renderFindings() {
  const text = ($("filter").value || "").toLowerCase();
  const tb = $("findings").querySelector("tbody");
  tb.innerHTML = "";
  const shown = lastFindings.filter(f => !text ||
    (f.name + " " + f.path + " " + f.kind + " " + f.message).toLowerCase().includes(text));
  $("findings").style.display = shown.length ? "table" : "none";
  $("clean-msg").style.display = shown.length ? "none" : "block";
  $("clean-msg").textContent = lastFindings.length ?
    "No findings match the filter." : "No threats found.";
  for (const f of shown) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td><span class="badge ' + sevClass(f.severity) + '">' + esc(f.severity).toUpperCase() + '</span></td>' +
      '<td><b>' + esc(f.name) + '</b><div class="muted">' + esc(f.message) + '</div></td>' +
      '<td class="muted">' + esc(f.kind) + '</td>' +
      '<td>' + esc(f.path) + '</td>';
    tb.appendChild(tr);
  }
}

/* ----------------------------------------------------------------- jobs */
async function loadJobs() {
  const r = await api("/api/jobs");
  if (!r.ok) return;
  const ul = $("jobs");
  ul.innerHTML = "";
  for (const j of r.data.jobs) {
    const li = document.createElement("li");
    if (j.id === (currentJob && currentJob.id)) li.className = "active";
    li.innerHTML = '<b>' + esc(j.target) + '</b> <span class="muted">[' + j.status + '] ' +
      j.files_scanned + ' files / ' + j.findings + ' findings</span>';
    li.onclick = () => viewJob(j.id);
    ul.appendChild(li);
  }
  if (!r.data.jobs.length) ul.innerHTML = '<li class="muted" style="cursor:default">No scans yet.</li>';
}
async function viewJob(id) {
  const r = await api("/api/jobs/" + id);
  if (r.ok && r.data.result) showResult(r.data.result);
}

/* ------------------------------------------------------------- quarantine */
async function loadQuarantine() {
  const r = await api("/api/quarantine");
  if (!r.ok) return;
  const items = r.data.items;
  $("qtable").style.display = items.length ? "table" : "none";
  $("q-empty").style.display = items.length ? "none" : "block";
  const tb = $("qtable").querySelector("tbody");
  tb.innerHTML = "";
  for (const i of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td>' + esc(i.id) + '</td>' +
      '<td class="muted">' + esc(i.original_path) + '<div class="muted">' + esc(i.reason) + '</div></td>' +
      '<td style="white-space:nowrap"><button class="small ghost" onclick="qRestore(\'' + esc(i.id) + '\')">restore</button> ' +
      '<button class="small danger" onclick="qPurge(\'' + esc(i.id) + '\')">purge</button></td>';
    tb.appendChild(tr);
  }
}
async function qRestore(id) { const r = await api("/api/quarantine/restore", {id}); if (!r.ok) alert(r.data.error || "restore failed"); loadQuarantine(); }
async function qPurge(id) { if (!confirm("Purge permanently?")) return; const r = await api("/api/quarantine/purge", {id}); if (!r.ok) alert(r.data.error || "purge failed"); loadQuarantine(); }

/* -------------------------------------------------------------- signatures */
async function loadSigs() {
  const r = await api("/api/signatures");
  if (!r.ok) return;
  const sigs = r.data.signatures;
  $("sigtable").style.display = sigs.length ? "table" : "none";
  const tb = $("sigtable").querySelector("tbody");
  tb.innerHTML = "";
  for (const s of sigs) {
    const kind = [s.sha256 && "sha256", s.md5 && "md5", s.pattern && "pattern"].filter(Boolean).join("+");
    const tr = document.createElement("tr");
    tr.innerHTML = '<td>' + esc(s.id) + '</td>' +
      '<td><span class="badge ' + sevClass(s.severity) + '">' + esc(s.severity) + '</span></td>' +
      '<td>' + esc(s.name) + ' <span class="muted">' + esc(kind) + '</span></td>' +
      '<td><button class="small danger" onclick="sigRemove(\'' + esc(s.id) + '\')">\u2715</button></td>';
    tb.appendChild(tr);
  }
}
$("sig-form").addEventListener("submit", async e => {
  e.preventDefault();
  const kind = document.querySelector('input[name="sigkind"]:checked').value;
  const value = $("sig-value").value.trim();
  const id = $("sig-id").value.trim();
  if (!id || !value) { alert("id and pattern/hash are required"); return; }
  const body = {id: id, name: $("sig-name").value.trim() || id,
                severity: $("sig-sev").value};
  body[kind] = value;
  const r = await api("/api/signatures", body);
  if (!r.ok) { alert("Add failed: " + (r.data.error || r.status)); return; }
  loadSigs();
});
async function sigRemove(id) { const r = await api("/api/signatures/remove", {id}); if (!r.ok) alert(r.data.error || "remove failed"); loadSigs(); }

/* --------------------------------------------------------- quick file check */
async function quickScan() {
  const path = $("qpath").value.trim();
  const out = $("qout");
  if (!path) return;
  out.style.display = "block";
  out.textContent = "inspecting " + path + " …";
  const r = await api("/api/fileinfo?path=" + encodeURIComponent(path));
  if (!r.ok) { out.textContent = "error: " + (r.data.error || r.status); return; }
  const d = r.data;
  let text =
    "type:   " + d.type + "\n" +
    "size:   " + d.size + " bytes    mtime: " + d.mtime_iso + "\n" +
    "sha256: " + d.sha256 + "\n" +
    "md5:    " + d.md5 + "\n\n";
  text += d.findings.length ?
    d.findings.length + " finding(s):\n" +
    d.findings.map(f => "  [" + f.severity + "] " + f.name + " — " + f.message).join("\n") :
    "no findings";
  out.textContent = text;
}

/* ------------------------------------------------------------- reports */
async function loadReports() {
  const [list, sum] = await Promise.all([api("/api/reports"), api("/api/reports/summary")]);
  if (!list.ok) return;
  const el = $("reports");
  let text = "summary: " + sum.data.reports + " report(s), " +
    sum.data.infected + " infected, " + sum.data.total_findings +
    " total finding(s)\n";
  const top = (sum.data.top_indicators || []).slice(0, 3);
  if (top.length) text += "top: " + top.map(t => t.name + " ×" + t.count).join(", ") + "\n";
  text += "latest: ";
  const recent = list.data.reports.slice(-4).reverse();
  el.textContent = text + (recent.length ? "" : "none");
  for (const r of recent) {
    el.textContent += "\n· " + r.name + " — " + (r.clean ? "clean" : r.findings + " finding(s)");
  }
}

/* ------------------------------------------------------------- engine stats */
function fmtBytes(n) {
  if (n == null) return "0 B";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1048576).toFixed(1) + " MiB";
}
async function loadStats() {
  const r = await api("/api/stats");
  if (!r.ok) return;
  const s = r.data, el = $("stats");
  const sev = Object.entries(s.signatures.by_severity).map(([k,v]) => k + "×" + v).join(", ");
  let text = "v" + s.version + "\n";
  text += "signatures: " + s.signatures.total + (sev ? "  (" + sev + ")" : "") + "\n";
  text += "scan cache: " + s.cache.entries + " entries · " + fmtBytes(s.cache.size_bytes) + "\n";
  text += "quarantine: " + s.quarantine.items + " item(s)";
  if (s.reports) text += "\nreports: " + s.reports.reports + " total · " +
    s.reports.infected + " infected · " + s.reports.total_findings + " finding(s)";
  el.textContent = text;
}

/* ------------------------------------------------------------- rescue disk */
async function loadRescue() {
  const r = await api("/api/rescue");
  const el = $("rescue");
  if (!r.ok) { el.textContent = "no rescue kit yet — press build"; return; }
  const d = r.data;
  let text = "kit: " + d.kit;
  if (d.iso) text += "\niso: " + d.iso + " (" + fmtBytes(d.iso_size) + ")";
  text += "\nsignatures: " + d.signatures + " · files: " + d.files + "\nbuilt: " + d.built;
  el.textContent = text;
}
async function rescueBuild() {
  const r = await api("/api/rescue/build", {});
  if (!r.ok) { alert("Rescue build failed: " + (r.data.error || r.status)); return; }
  loadRescue();
}

/* ------------------------------------------------------------- fast verify */
async function verifyBaseline() {
  const target = $("target").value.trim() || ".";
  const baseline = $("baseline").value;
  if (!baseline) { alert("Pick a baseline first (or create one)."); return; }
  const r = await api("/api/verify?target=" + encodeURIComponent(target) +
                      "&baseline=" + encodeURIComponent(baseline));
  if (!r.ok) { alert("Verify failed: " + (r.data.error || r.status)); return; }
  const d = r.data;
  if (d.clean) { alert("Integrity check clean — no changes since " + baseline + "."); return; }
  showResult({target: d.target, findings: d.findings, files_scanned: 0, clean: false});
  $("result-target").textContent = " — " + d.target + "  [integrity: " +
    d.changed + " changed, " + d.missing + " missing, " + d.new + " new]";
}

init();
</script>
</body>
</html>
"""


DOCS_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AntiVirus API</title>
<style>
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
     background:#0d1117;color:#e6edf3;max-width:900px;margin:0 auto;padding:24px}
h1{font-size:20px}
code{background:#161b22;border:1px solid #30363d;border-radius:4px;
     padding:1px 6px;font-size:13px}
table{border-collapse:collapse;width:100%;margin:14px 0}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;
      vertical-align:top;font-size:13px}
th{background:#161b22}
.mut{color:#8b949e}
a{color:#2f81f7}
</style>
</head>
<body>
<h1>AntiVirus Web Console — JSON API</h1>
<p class="mut">Local tool — no authentication. All endpoints are JSON
(UTF-8); <code>POST</code> bodies are JSON objects. <a href="/">← back to the console</a></p>
<table>
<tr><th>Endpoint</th><th>Method</th><th>Purpose</th></tr>
<tr><td><code>/api/health</code></td><td>GET</td><td>engine status + version</td></tr>
<tr><td><code>/api/scan</code></td><td>POST</td><td>start a scan job —
    <code>{"target","action","fast","no_archives","since","baseline"}</code></td></tr>
<tr><td><code>/api/jobs</code></td><td>GET</td><td>all jobs (summary)</td></tr>
<tr><td><code>/api/jobs/&lt;id&gt;</code></td><td>GET</td><td>job progress,
    <code>findings_preview</code> (live), and the full <code>result</code> when done</td></tr>
<tr><td><code>/api/quarantine</code></td><td>GET</td><td>quarantined items</td></tr>
<tr><td><code>/api/quarantine/restore</code> / <code>/api/quarantine/purge</code></td><td>POST</td><td><code>{"id"}</code></td></tr>
<tr><td><code>/api/signatures</code></td><td>GET / POST</td><td>list / add signatures
    (<code>id,name,severity,category,description,sha256,md5,pattern</code>)</td></tr>
<tr><td><code>/api/signatures/remove</code></td><td>POST</td><td><code>{"id"}</code></td></tr>
<tr><td><code>/api/baselines</code></td><td>GET</td><td>list integrity baselines (manifests)</td></tr>
<tr><td><code>/api/baselines</code></td><td>POST</td><td>create one —
    <code>{"target","id?"}</code>; pass the returned <code>id</code> as
    <code>baseline</code> in <code>/api/scan</code> to report changed /
    missing / new files</td></tr>
<tr><td><code>/api/fileinfo</code></td><td>GET</td><td><code>?path=…</code> —
    type (magic), size, mtime, SHA-256/MD5 plus a single-file scan
    (<code>findings</code>)</td></tr>
<tr><td><code>/api/reports</code></td><td>GET</td><td>saved reports (list)</td></tr>
<tr><td><code>/api/reports/summary</code></td><td>GET</td><td>aggregate of all saved reports</td></tr>
<tr><td><code>/api/verify</code></td><td>GET</td><td><code>?target=&amp;baseline=</code> —
    fast integrity check (hash + diff, no signature scan); returns
    <code>changed/missing/new</code> counts and the findings</td></tr>
<tr><td><code>/api/stats</code></td><td>GET</td><td>engine statistics: signature
    counts by severity/kind, scan-cache size, quarantine items, report totals</td></tr>
<tr><td><code>/api/rescue/build</code></td><td>POST</td><td>build the rescue kit
    + ISO image — <code>{"out"?, "iso"?}</code>; returns kit/iso paths and
    the signature count</td></tr>
<tr><td><code>/api/rescue</code></td><td>GET</td><td>last rescue build (404 until
    one exists)</td></tr>
<tr><td><code>/api/kill</code></td><td>GET</td><td>kill registry — every
    in-place killed file with its stored key/IV</td></tr>
<tr><td><code>/api/kill/revive</code></td><td>POST</td><td><code>{"id"}</code> —
    restore a killed file's original bytes using the registry's key/IV</td></tr>
<tr><td><code>/api/kill/purge</code></td><td>POST</td><td><code>{"id"}</code> —
    permanently delete a killed file and its registry entry</td></tr>
<tr><td><code>/api/docs</code></td><td>GET</td><td>this page</td></tr>
</table>
<h2>Example (curl)</h2>
<pre>curl -s -X POST localhost:8420/api/scan -d '{{"target":".","action":"detect"}}'
curl -s localhost:8420/api/jobs/&lt;id&gt;
curl -s -X POST localhost:8420/api/baselines -d '{{"target":"."}}'
curl -s -X POST localhost:8420/api/scan \\
     -d '{{"target":".","baseline":"baseline-20260928-120000"}}'</pre>
</body>
</html>
"""


# ---------------------------------------------------------------------- jobs
class ScanJob:
    """One scan running in a background thread (progress-pollable)."""

    def __init__(self, scanner: Scanner, target: Path, action: str = "detect",
                 quarantine: Optional[Quarantine] = None,
                 baseline: Optional[Path] = None,
                 report_writer=None,
                 kill_registry: Optional[KillRegistry] = None) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.target = str(target)
        self.action = action
        self.baseline: Optional[str] = str(baseline) if baseline else None
        self.status = "running"
        self.error: Optional[str] = None
        self.started_at = time.time()
        self.finished_at: Optional[float] = None
        self.notes: Dict[str, str] = {}
        self.result = ScanResult(target=self.target, started_at=self.started_at)
        self._scanner = scanner
        self._target = Path(target)
        self._quarantine = quarantine
        self._kill_registry = kill_registry
        self._baseline = baseline
        self._report_writer = report_writer
        self.report_path = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            from .api import neutralized_map

            self._scanner.neutralized = neutralized_map(self._kill_registry)
            self._scanner.scan_path(self._target, result=self.result)
            if self._baseline is not None and self._target.is_dir():
                from .integrity import (
                    compare_baseline,
                    current_from_result,
                    load_manifest,
                )

                manifest = load_manifest(self._baseline)
                extra = compare_baseline(
                    manifest, current_from_result(self.result, self._target))
                if extra:
                    self.result.findings.extend(extra)
            if self.action != "detect":
                from .api import apply_actions

                self.notes = apply_actions(self.result, self._quarantine,
                                           self.action,
                                           kill_registry=self._kill_registry)
            if self._report_writer is not None:
                self.report_path = self._report_writer.save(
                    self.result, action=self.action,
                    actions_taken=self.notes)
            self.status = "done"
        except Exception as exc:  # the UI needs a reason, not a traceback
            self.status = "error"
            self.error = str(exc)
        finally:
            self.result.finished_at = time.time()
            self.finished_at = self.result.finished_at

    def findings_preview(self, limit: int = 100) -> List[dict]:
        """Lightweight findings collected so far (for live progress UIs)."""
        return [f.to_dict() for f in self.result.findings[:limit]]

    def progress(self) -> dict:
        r = self.result
        now = self.finished_at or time.time()
        return {
            "id": self.id,
            "target": self.target,
            "action": self.action,
            "baseline": self.baseline,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "elapsed_seconds": round(now - self.started_at, 3),
            "files_scanned": r.files_scanned,
            "files_skipped": r.files_skipped,
            "files_cached": r.files_cached,
            "bytes_scanned": r.bytes_scanned,
            "findings": len(r.findings),
        }

    def result_dict(self) -> Optional[dict]:
        if self.status != "done":
            return None
        data = self.result.to_dict()
        data["action"] = self.action
        data["actions_taken"] = self.notes
        if self.report_path is not None:
            data["report"] = str(self.report_path)
        return data


# ------------------------------------------------------------------------ app
class WebApp:
    """State shared by all HTTP requests: jobs + collaborators."""

    def __init__(self, config: Config, db: SignatureDB,
                 scanner: Scanner, quarantine: Quarantine) -> None:
        self.config = config
        self.db = db
        self.scanner = scanner
        self.quarantine = quarantine
        self.kill_registry = KillRegistry(config.registry_dir)
        self.jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def start_scan(self, target: Path, action: str = "detect",
                   options: Optional[dict] = None) -> ScanJob:
        """Start a scan job with per-request options (own config + scanner)."""
        cfg = copy.copy(self.config)
        opts = options or {}
        if opts.get("fast"):
            cfg.fast_mode = True
        if opts.get("no_archives"):
            cfg.archives_enabled = False
        if opts.get("no_behavior"):
            cfg.behavior_enabled = False
        since = str(opts.get("since") or "").strip()
        if since:
            try:
                cfg.since_ts = time.time() - parse_since(since)
            except ValueError as exc:
                raise ValueError(f"invalid --since duration: {since!r}") from exc
        baseline_path: Optional[Path] = None
        if opts.get("baseline"):
            baseline_path = self.resolve_baseline(str(opts["baseline"]))
            if baseline_path is None:
                raise ValueError(f"no such baseline: {opts['baseline']!r}")
            # A baseline comparison needs the *current* hash of every file;
            # cached verdicts carry no digests, so bypass the cache.
            cfg.cache_enabled = False
        scanner = Scanner(cfg, self.db)
        from .report import ReportWriter

        job = ScanJob(scanner, target, action, self.quarantine,
                      baseline=baseline_path,
                      report_writer=ReportWriter(self.config.report_dir),
                      kill_registry=self.kill_registry)
        with self._lock:
            self.jobs[job.id] = job
            if len(self.jobs) > 64:  # keep the job table bounded
                for key in sorted(self.jobs, key=self.jobs.get.started_at)[: 20]:
                    del self.jobs[key]
        job.thread.start()
        return job

    def jobs_summary(self) -> List[dict]:
        with self._lock:
            jobs = list(self.jobs.values())
        return [j.progress() for j in sorted(jobs, key=lambda j: j.started_at,
                                             reverse=True)]

    def job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self.jobs.get(job_id)

    def job_detail(self, job_id: str) -> Optional[dict]:
        job = self.job(job_id)
        if job is None:
            return None
        data = {"job": job.progress(),
                "findings_preview": job.findings_preview()}
        result = job.result_dict()
        if result is not None:
            data["result"] = result
        return data

    # -------------------------------------------------------- baselines (FIM)
    def create_baseline(self, target: Path, baseline_id: Optional[str] = None
                        ) -> dict:
        from .integrity import build_manifest, save_manifest

        target = Path(target)
        if not target.exists():
            raise FileNotFoundError(str(target))
        manifest = build_manifest(target, self.config)
        if not baseline_id:
            baseline_id = "baseline-" + time.strftime("%Y%m%d-%H%M%S")
        safe = "".join(c for c in str(baseline_id) if c.isalnum() or c in "-_")
        bpath = self.config.baseline_dir / f"{safe}.json"
        save_manifest(manifest, bpath)
        return {"id": bpath.stem, "path": str(bpath),
                "files": len(manifest["files"])}

    def list_baselines(self) -> List[dict]:
        out: List[dict] = []
        bdir = self.config.baseline_dir
        if bdir.is_dir():
            for p in sorted(bdir.glob("*.json")):
                out.append({"id": p.stem, "path": str(p)})
        return out

    def resolve_baseline(self, ref: str) -> Optional[Path]:
        """Resolve a baseline reference: path, or id in the baseline dir."""
        p = Path(ref)
        if p.exists():
            return p
        candidate = self.config.baseline_dir / f"{ref}.json"
        return candidate if candidate.exists() else None

    # --------------------------------------------------------- verify/stats
    def verify(self, target: Path, baseline_ref: str) -> dict:
        """Fast integrity-only check (hash + diff, no signature scan)."""
        from .integrity import CHANGED, MISSING, NEW, load_manifest, verify_tree

        bpath = self.resolve_baseline(baseline_ref)
        if bpath is None:
            raise ValueError(f"no such baseline: {baseline_ref!r}")
        baseline = load_manifest(bpath)
        findings = verify_tree(target, baseline, self.config)
        return {
            "target": str(target),
            "baseline": str(bpath),
            "changed": sum(1 for f in findings if f.name == CHANGED),
            "missing": sum(1 for f in findings if f.name == MISSING),
            "new": sum(1 for f in findings if f.name == NEW),
            "clean": not findings,
            "findings": [f.to_dict() for f in findings],
        }

    def stats(self) -> dict:
        from .api import engine_stats

        return engine_stats(self.config, self.db, self.quarantine)

    # -------------------------------------------------------------- rescue
    def rescue_build(self, out_dir: Optional[str] = None,
                     iso_path: Optional[str] = None) -> dict:
        from .rescue import build_rescue_disk

        out = Path(out_dir) if out_dir else Path.cwd() / "rescue-kit"
        iso = Path(iso_path) if iso_path else Path.cwd() / "rescue.iso"
        info = build_rescue_disk(out, iso, self.config.signatures_file)
        self.last_rescue = {
            "kit": str(out),
            "iso": str(iso),
            "iso_size": info.get("iso_size"),
            "antivirus": info["antivirus"],
            "signatures": info["signatures"]["count"],
            "files": len(info["files"]),
            "built": info["built"],
        }
        return info

    def rescue_status(self) -> Optional[dict]:
        if getattr(self, "last_rescue", None):
            return self.last_rescue
        from .rescue import read_kit_manifest

        manifest = read_kit_manifest(Path.cwd() / "rescue-kit")
        if manifest is None:
            return None
        iso = Path.cwd() / "rescue.iso"
        return {
            "kit": str(Path.cwd() / "rescue-kit"),
            "iso": str(iso) if iso.exists() else None,
            "iso_size": iso.stat().st_size if iso.exists() else None,
            "antivirus": manifest["antivirus"],
            "signatures": manifest["signatures"]["count"],
            "files": len(manifest["files"]),
            "built": manifest["built"],
        }

    # ------------------------------------------------------- file utilities
    def file_info(self, path: str) -> Optional[dict]:
        from .fileinfo import file_info

        p = Path(path)
        if not p.exists():
            return None
        info = file_info(p)
        info["findings"] = [f.to_dict()
                            for f in self.scanner.scan_file(p)]
        return info

    # ---------------------------------------------------------------- reports
    def reports(self) -> List[dict]:
        out: List[dict] = []
        for p in self.report_paths():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out.append({
                "name": p.name,
                "target": data.get("target"),
                "clean": bool(data.get("clean")),
                "findings": len(data.get("findings", [])),
                "mtime": p.stat().st_mtime,
            })
        return out

    def report_summary(self) -> dict:
        from .report import summarize_reports

        return summarize_reports(self.report_paths())

    def report_paths(self) -> List[Path]:
        from .report import ReportWriter

        return ReportWriter(self.config.report_dir).all_reports()


# --------------------------------------------------------------------- handler
class _Handler(BaseHTTPRequestHandler):
    server_version = "AntiVirus/" + __version__

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:  # keep stdout readable
        import sys

        sys.stderr.write("[web] %s\n" % (fmt % args))

    def _send(self, code: int, body: bytes,
              ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _body(self) -> Optional[dict]:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        if n > 1_000_000:
            return None
        try:
            data = json.loads(self.rfile.read(n))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _path(self) -> str:
        return unquote(urlsplit(self.path).path)

    @property
    def app(self) -> WebApp:
        return self.server.app  # type: ignore[attr-defined]

    # -- routes ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        path = self._path()
        try:
            if path in ("/", "/index.html", "/ui"):
                self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/api/health":
                self._json(200, {"ok": True, "version": __version__})
            elif path == "/api/jobs":
                self._json(200, {"jobs": self.app.jobs_summary()})
            elif path.startswith("/api/jobs/"):
                detail = self.app.job_detail(path.rsplit("/", 1)[-1])
                if detail is None:
                    self._json(404, {"error": "no such job"})
                else:
                    self._json(200, detail)
            elif path == "/api/quarantine":
                items = [asdict(i) for i in self.app.quarantine.items()]
                self._json(200, {"items": items})
            elif path == "/api/signatures":
                sigs = [asdict(s) for s in self.app.db.list()]
                self._json(200, {"signatures": sigs})
            elif path == "/api/baselines":
                self._json(200, {"baselines": self.app.list_baselines()})
            elif path == "/api/fileinfo":
                self._fileinfo()
            elif path == "/api/reports":
                self._json(200, {"reports": self.app.reports()})
            elif path == "/api/reports/summary":
                self._json(200, self.app.report_summary())
            elif path == "/api/stats":
                self._json(200, self.app.stats())
            elif path == "/api/verify":
                self._verify()
            elif path == "/api/rescue":
                status = self.app.rescue_status()
                if status is None:
                    self._json(404, {"error": "no rescue kit built yet"})
                else:
                    self._json(200, status)
            elif path == "/api/kill":
                items = [asdict(i) for i in self.app.kill_registry.entries()]
                self._json(200, {"items": items,
                                 "registry": str(self.app.kill_registry.path)})
            elif path == "/api/docs":
                self._send(200, DOCS_PAGE.encode("utf-8"),
                           "text/html; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:  # noqa: N802
        path = self._path()
        try:
            if path == "/api/scan":
                self._scan()
            elif path == "/api/rescue/build":
                self._rescue_build()
            elif path in ("/api/kill/revive", "/api/kill/purge"):
                self._kill_op("revive" if path.endswith("revive") else "purge")
            elif path == "/api/baselines":
                self._baseline_create()
            elif path == "/api/quarantine/restore":
                self._quarantine_op("restore")
            elif path == "/api/quarantine/purge":
                self._quarantine_op("purge")
            elif path == "/api/signatures":
                self._sig_add()
            elif path == "/api/signatures/remove":
                self._sig_remove()
            else:
                self._json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- route handlers ---------------------------------------------------------
    def _scan(self) -> None:
        body = self._body()
        if body is None:
            self._json(400, {"error": "invalid JSON body"})
            return
        target = str(body.get("target") or "").strip()
        if not target:
            self._json(400, {"error": "target is required"})
            return
        if not Path(target).exists():
            self._json(404, {"error": f"no such file or directory: {target}"})
            return
        action = str(body.get("action") or "detect")
        if action not in ("detect", "quarantine", "kill", "delete"):
            self._json(400, {"error": f"invalid action: {action}"})
            return
        options = {
            "fast": bool(body.get("fast")),
            "no_archives": bool(body.get("no_archives")),
            "no_behavior": bool(body.get("no_behavior")),
            "since": body.get("since") or "",
            "baseline": str(body.get("baseline") or "").strip(),
        }
        try:
            job = self.app.start_scan(Path(target), action, options)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, {"job": job.progress()})

    def _baseline_create(self) -> None:
        body = self._body()
        if body is None:
            self._json(400, {"error": "invalid JSON body"})
            return
        target = str(body.get("target") or "").strip()
        if not target:
            self._json(400, {"error": "target is required"})
            return
        try:
            info = self.app.create_baseline(Path(target),
                                            body.get("id") or None)
        except FileNotFoundError:
            self._json(404, {"error": f"no such file or directory: {target}"})
            return
        except (OSError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, info)

    def _fileinfo(self) -> None:
        from urllib.parse import parse_qs

        query = parse_qs(urlsplit(self.path).query)
        path = (query.get("path") or [""])[0].strip()
        if not path:
            self._json(400, {"error": "path query parameter is required"})
            return
        info = self.app.file_info(path)
        if info is None:
            self._json(404, {"error": f"no such file: {path}"})
            return
        self._json(200, info)

    def _verify(self) -> None:
        from urllib.parse import parse_qs

        query = parse_qs(urlsplit(self.path).query)
        target = (query.get("target") or [""])[0].strip()
        baseline = (query.get("baseline") or [""])[0].strip()
        if not target or not baseline:
            self._json(400, {"error": "target and baseline query parameters "
                                      "are required"})
            return
        if not Path(target).exists():
            self._json(404, {"error": f"no such file or directory: {target}"})
            return
        try:
            self._json(200, self.app.verify(Path(target), baseline))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})

    def _rescue_build(self) -> None:
        body = self._body() or {}
        try:
            info = self.app.rescue_build(body.get("out"), body.get("iso"))
        except (OSError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, {
            "kit": info["kit"],
            "iso": info["iso"],
            "iso_size": info.get("iso_size"),
            "antivirus": info["antivirus"],
            "signatures": info["signatures"]["count"],
            "files": len(info["files"]),
            "built": info["built"],
        })

    def _quarantine_op(self, op: str) -> None:
        body = self._body()
        qid = str((body or {}).get("id") or "").strip()
        if not qid:
            self._json(400, {"error": "id is required"})
            return
        try:
            if op == "restore":
                item, target = self.app.quarantine.restore(qid)
                self._json(200, {"ok": True, "id": item.id,
                                 "restored_to": str(target)})
            else:
                self.app.quarantine.purge(qid)
                self._json(200, {"ok": True, "id": qid})
        except (KeyError, ValueError, FileNotFoundError) as exc:
            self._json(404, {"error": str(exc)})

    def _kill_op(self, op: str) -> None:
        body = self._body()
        kid = str((body or {}).get("id") or "").strip()
        if not kid:
            self._json(400, {"error": "id is required"})
            return
        try:
            if op == "revive":
                item, target = self.app.kill_registry.revive(kid)
                self._json(200, {"ok": True, "id": item.id,
                                 "revived_to": str(target),
                                 "size": item.size})
            else:
                self.app.kill_registry.purge(kid)
                self._json(200, {"ok": True, "id": kid})
        except (KeyError, ValueError, FileNotFoundError) as exc:
            self._json(404, {"error": str(exc)})

    def _sig_add(self) -> None:
        body = self._body()
        if body is None:
            self._json(400, {"error": "invalid JSON body"})
            return
        sig = Signature(
            id=str(body.get("id") or "").strip(),
            name=str(body.get("name") or "").strip(),
            category=str(body.get("category") or "custom"),
            severity=str(body.get("severity") or "medium"),
            description=str(body.get("description") or ""),
            sha256=str(body.get("sha256") or "").lower(),
            md5=str(body.get("md5") or "").lower(),
            pattern=str(body.get("pattern") or ""),
        )
        if not sig.id:
            self._json(400, {"error": "id is required"})
            return
        try:
            self.app.db.add(sig)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, {"ok": True, "id": sig.id})

    def _sig_remove(self) -> None:
        body = self._body()
        sig_id = str((body or {}).get("id") or "").strip()
        if not sig_id:
            self._json(400, {"error": "id is required"})
            return
        try:
            removed = self.app.db.remove(sig_id)
        except KeyError as exc:
            self._json(404, {"error": exc.args[0]})
            return
        self._json(200, {"ok": True, "id": removed.id})


# ---------------------------------------------------------------------- entry
def run_web(config: Config, db: SignatureDB, scanner: Scanner,
            quarantine: Quarantine, host: str = "0.0.0.0",
            port: int = 8420) -> int:
    """Serve the web console until Ctrl+C; returns the exit code."""
    app = WebApp(config, db, scanner, quarantine)
    server = ThreadingHTTPServer((host, port), _Handler)
    server.app = app  # type: ignore[attr-defined]
    shown = "localhost" if host in ("0.0.0.0", "::", "") else host
    print(f"AntiVirus web console  (v{__version__})")
    print(f"  http://{shown}:{port}   (Ctrl+C to stop)")
    print("  local tool – no authentication; do not expose to untrusted "
          "networks")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping web console…")
    finally:
        server.server_close()
    return 0
