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
form.scan{display:grid;grid-template-columns:1fr 150px 150px;gap:8px}
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
          <option value="delete">delete</option>
        </select>
        <input id="since" placeholder="since (e.g. 2h) – empty = all">
        <div style="display:flex;gap:14px;align-items:center;grid-column:1/-1">
          <label class="opt"><input type="checkbox" id="fast" style="width:auto"> fast (hash+pattern only)</label>
          <label class="opt"><input type="checkbox" id="no-archives" style="width:auto"> skip archives</label>
          <button type="submit">Scan</button>
        </div>
      </form>
      <div id="job-status" class="muted" style="display:none">
        <div class="progress"><div id="progress-bar"></div></div>
        <span id="progress-text"></span>
      </div>
    </section>
    <section style="margin-top:14px">
      <h2>Results <span class="muted" id="result-target"></span></h2>
      <div class="summary" id="summary"></div>
      <table id="findings" style="display:none">
        <thead><tr><th>Severity</th><th>Finding</th><th>Kind</th><th>File</th></tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty" id="clean-msg" style="display:none">No threats found.</div>
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
  </div>
</main>
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
let currentJob = null, pollTimer = null;

function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
function sevClass(s) { return ["critical","high","medium","low","info"].includes(s) ? s : "info"; }

async function init() {
  const h = await api("/api/health");
  $("ver").textContent = "v" + (h.data.version || "?");
  if (!h.ok) $("engine-dot").style.background = "var(--red)";
  loadJobs(); loadQuarantine(); loadSigs();
  setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString(); }, 1000);
}

$("scan-form").addEventListener("submit", async e => {
  e.preventDefault();
  const body = {target: $("target").value.trim() || ".", action: $("action").value,
                fast: $("fast").checked, no_archives: $("no-archives").checked};
  const since = $("since").value.trim();
  if (since) body.since = since;
  const r = await api("/api/scan", body);
  if (!r.ok) { alert("Scan failed: " + (r.data.error || r.status)); return; }
  currentJob = r.data.job;
  startPolling();
});

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  $("job-status").style.display = "block";
  $("progress-bar").style.width = "8%";
  pollTimer = setInterval(pollJob, 1000);
  pollJob();
}
async function pollJob() {
  if (!currentJob) return;
  const r = await api("/api/jobs/" + currentJob.id);
  if (!r.ok) { stopPolling(); return; }
  const j = r.data.job;
  $("progress-text").textContent = j.target + " — " + j.files_scanned +
    " file(s), " + (j.bytes_scanned / 1048576).toFixed(1) + " MiB, " +
    j.findings + " finding(s)";
  if (j.status === "running") {
    $("progress-bar").style.width = "40%";
    loadJobs();
  } else {
    stopPolling();
    $("progress-bar").style.width = "100%";
    if (j.status === "error") alert("Scan error: " + j.error);
    if (r.data.result) showResult(r.data.result);
    loadJobs(); loadQuarantine();
  }
}
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

function showResult(d) {
  $("result-target").textContent = " — " + d.target;
  const n = d.findings.length;
  $("summary").innerHTML =
    '<div class="card"><div class="num">' + d.files_scanned + '</div><div class="muted">files</div></div>' +
    '<div class="card"><div class="num">' + n + '</div><div class="muted">threats</div></div>' +
    '<div class="card"><div class="num">' + d.files_cached + '</div><div class="muted">cached</div></div>' +
    '<div class="card"><div class="num">' + d.elapsed_seconds + 's</div><div class="muted">duration</div></div>';
  const tb = $("findings").querySelector("tbody");
  tb.innerHTML = "";
  $("findings").style.display = n ? "table" : "none";
  $("clean-msg").style.display = n ? "none" : "block";
  for (const f of d.findings) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td><span class="badge ' + sevClass(f.severity) + '">' + esc(f.severity).toUpperCase() + '</span></td>' +
      '<td><b>' + esc(f.name) + '</b><div class="muted">' + esc(f.message) + '</div></td>' +
      '<td class="muted">' + esc(f.kind) + '</td>' +
      '<td>' + esc(f.path) + '</td>';
    tb.appendChild(tr);
  }
}

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

init();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------- jobs
class ScanJob:
    """One scan running in a background thread (progress-pollable)."""

    def __init__(self, scanner: Scanner, target: Path, action: str = "detect",
                 quarantine: Optional[Quarantine] = None) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.target = str(target)
        self.action = action
        self.status = "running"
        self.error: Optional[str] = None
        self.started_at = time.time()
        self.finished_at: Optional[float] = None
        self.notes: Dict[str, str] = {}
        self.result = ScanResult(target=self.target, started_at=self.started_at)
        self._scanner = scanner
        self._target = Path(target)
        self._quarantine = quarantine
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self._scanner.scan_path(self._target, result=self.result)
            if self.action != "detect":
                handled = set()
                for finding in self.result.findings:
                    if finding.path in handled:
                        continue
                    handled.add(finding.path)
                    path = Path(finding.path)
                    if not path.exists():
                        self.notes[finding.path] = "already gone"
                    elif self.action == "quarantine":
                        try:
                            item = self._quarantine.put(path, finding)
                            self.notes[finding.path] = f"quarantined as {item.id}"
                        except OSError as exc:
                            self.notes[finding.path] = f"quarantine failed: {exc}"
                    else:  # delete
                        try:
                            path.unlink()
                            self.notes[finding.path] = "deleted"
                        except OSError as exc:
                            self.notes[finding.path] = f"delete failed: {exc}"
            self.status = "done"
        except Exception as exc:  # the UI needs a reason, not a traceback
            self.status = "error"
            self.error = str(exc)
        finally:
            self.result.finished_at = time.time()
            self.finished_at = self.result.finished_at

    def progress(self) -> dict:
        r = self.result
        now = self.finished_at or time.time()
        return {
            "id": self.id,
            "target": self.target,
            "action": self.action,
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
        scanner = Scanner(cfg, self.db)
        job = ScanJob(scanner, target, action, self.quarantine)
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
        data = {"job": job.progress()}
        result = job.result_dict()
        if result is not None:
            data["result"] = result
        return data


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
            else:
                self._json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self) -> None:  # noqa: N802
        path = self._path()
        try:
            if path == "/api/scan":
                self._scan()
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
        if action not in ("detect", "quarantine", "delete"):
            self._json(400, {"error": f"invalid action: {action}"})
            return
        options = {
            "fast": bool(body.get("fast")),
            "no_archives": bool(body.get("no_archives")),
            "no_behavior": bool(body.get("no_behavior")),
            "since": body.get("since") or "",
        }
        try:
            job = self.app.start_scan(Path(target), action, options)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, {"job": job.progress()})

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
