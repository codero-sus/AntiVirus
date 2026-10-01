"""Background real-time guard — ``antivirus guard``.

Auto-scans **new and changed files** while running **detached in the
background** and **lightweight**:

    antivirus guard start ~/downloads --action quarantine
    antivirus guard status
    antivirus guard log
    antivirus guard stop

How it stays lightweight:

* **stat-only polling** — every *interval* seconds the tree is snapshotted
  and a file is only fully scanned when its ``mtime``/``size`` changed;
* **incremental walk** — directories whose ``(mtime, size)`` are unchanged
  are not re-``scandir``-ed; only their known children are stat'ed, so
  polling a large tree stays cheap (``cached_walk``);
* **no initial scan** by default — the guard watches from the moment it
  starts (``--initial`` runs one full scan at startup);
* **no report files** — events are appended to ``<state-dir>/guard.log``
  (rotated at 1 MiB); state lives in ``<state-dir>/guard.json``.

Everything the guard produces (pid, state, log, quarantine, kill
registry) lives under one **state dir** (default: ``./guard``).  The
daemon detaches from the terminal: on POSIX via ``setsid`` (new session,
stdio to ``/dev/null``), on Windows via a detached process with no
console window.  Stopping writes a sentinel file; the daemon exits at the
next poll (graceful, on every platform), with a force-kill fallback.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

#: State-dir file names.
PID_FILE = "guard.pid"
STATE_FILE = "guard.json"
LOG_FILE = "guard.log"
STOP_FILE = "guard.stop"

#: Maximum log size before rotation (1 MiB).
_MAX_LOG_SIZE = 1024 * 1024


# ------------------------------------------------------------------ platform
def pid_alive(pid: int) -> bool:
    """True when a process with *pid* is currently running."""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            SYNCHRONIZE = 0x00100000
            STILL_ACTIVE = 255
            handle = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
            if not handle:
                return False
            code = ctypes.c_uint32()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            kernel32.CloseHandle(handle)
            return bool(ok) and code.value == STILL_ACTIVE
        except Exception:  # pragma: no cover - odd environments
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # kill(0) also succeeds for zombies.  A process that has exited but was
    # never reaped (e.g. a daemon spawned by a test harness) must count as
    # dead, so check the state when the OS exposes it.
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
        state = data.rsplit(b")", 1)[1].lstrip()[:1]
        return state != b"Z"
    except (OSError, ValueError, IndexError):
        pass
    # No /proc (macOS etc.): if the zombie is our own child, reaping it tells
    # us it has exited; otherwise assume alive.
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        return True
    return done != pid


def _force_kill(pid: int) -> None:  # pragma: no cover - only on stuck daemons
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            PROCESS_TERMINATE = 0x0001
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, 0, pid)
            if handle:
                kernel32.TerminateProcess(handle, 1)
                kernel32.CloseHandle(handle)
        except Exception:
            pass
        return
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        return
    for _ in range(20):
        if not pid_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)  # SIGKILL
    except OSError:
        pass


def _spawn_kwargs() -> Dict:
    """Popen kwargs for a fully detached child (no terminal, no window)."""
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        return {
            "creationflags": (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
                              | CREATE_NO_WINDOW),
            "close_fds": True,
            "stdin": None, "stdout": None, "stderr": None,
        }
    return {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "start_new_session": True,
    }


def _package_root() -> Optional[str]:
    """A sys.path entry from which the ``antivirus`` package is importable.

    Lets the spawned daemon import the *same* package the parent uses
    (repo checkout, installed copy, or the rescue kit's dir/zip).
    """
    try:
        import antivirus  # noqa: F401
    except ImportError:
        return None
    for entry in sys.path:
        e = str(entry)
        if not e:
            e = os.getcwd()
        try:
            if (Path(e) / "antivirus").is_dir():
                return e
            if e.endswith(".zip") and Path(e).is_file():
                import zipfile

                with zipfile.ZipFile(e) as zf:
                    if any(n.startswith("antivirus/")
                           for n in zf.namelist()[:100]):
                        return e
        except (OSError, ValueError):
            continue
    return None


# --------------------------------------------------------------------- state
def _paths(state_dir: Path) -> Dict[str, Path]:
    s = Path(state_dir)
    return {"dir": s, "pid": s / PID_FILE, "state": s / STATE_FILE,
            "log": s / LOG_FILE, "stop": s / STOP_FILE}


def read_pid(state_dir: Path) -> Optional[int]:
    p = _paths(state_dir)["pid"]
    try:
        return int(p.read_text().strip() or 0) or None
    except (OSError, ValueError):
        return None


def read_state(state_dir: Path) -> Optional[Dict]:
    p = _paths(state_dir)["state"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def tail_log(state_dir: Path, lines: int = 30) -> List[str]:
    p = _paths(state_dir)["log"]
    if not p.exists():
        return []
    try:
        data = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return data[-lines:]
    except OSError:
        return []


def guard_running(state_dir: Path) -> Optional[int]:
    """The guard's pid when it is running, else None."""
    pid = read_pid(state_dir)
    if pid is not None and pid_alive(pid):
        return pid
    return None


def guard_status(state_dir: Path) -> Dict:
    state = read_state(state_dir) or {}
    pid = read_pid(state_dir)
    running = guard_running(state_dir) is not None
    out = {
        "running": running,
        "pid": pid if running else None,
        "state_dir": str(Path(state_dir)),
        "log": str(_paths(state_dir)["log"]),
        "target": state.get("target"),
        "action": state.get("action"),
        "interval": state.get("interval"),
        "started_at": state.get("started_at"),
        "stopped_at": state.get("stopped_at"),
        "files_scanned": state.get("files_scanned", 0),
        "threats_found": state.get("threats_found", 0),
        "last_event": state.get("last_event"),
        "version": state.get("version"),
    }
    return out


# -------------------------------------------------------------------- daemon
class GuardDaemon:
    """The actual watch loop (runs inside the detached process)."""

    def __init__(self, state_dir: Path, target: Path, action: str = "quarantine",
                 interval: float = 5.0, initial: bool = False,
                 signatures: Optional[str] = None) -> None:
        from . import __version__
        from .config import Config
        from .kill import KillRegistry
        from .monitor import DirectoryWatcher
        from .quarantine import Quarantine
        from .scanner import Scanner
        from .signatures import SignatureDB
        from .api import BUNDLED_SIGNATURES

        self.state_dir = Path(state_dir)
        self.target = Path(target)
        self.action = action
        self.interval = max(float(interval), 0.5)
        self.initial = initial
        self._paths = _paths(self.state_dir)

        config = Config()
        config.quarantine_dir = self.state_dir / "quarantine"
        config.report_dir = self.state_dir / "reports"
        config.registry_dir = self.state_dir / "registry"
        config.cache_dir = self.state_dir / ".av-cache"
        sig = Path(os.path.expanduser(str(signatures))) if signatures else None
        if sig is None or not sig.exists():
            sig = self.state_dir / "signatures.json"
            if not sig.exists() and BUNDLED_SIGNATURES.exists():
                sig.parent.mkdir(parents=True, exist_ok=True)
                import shutil

                shutil.copyfile(BUNDLED_SIGNATURES, sig)
        config.signatures_file = sig
        config.cache_enabled = True

        db = SignatureDB(config.signatures_file)
        scanner = Scanner(config, db)
        quarantine = Quarantine(config.quarantine_dir)
        kill_registry = KillRegistry(config.registry_dir)
        self._scanner = scanner
        self._config = config
        self.watcher = DirectoryWatcher(
            scanner, quarantine, action=action, interval=self.interval,
            log=self._log, on_event=self._on_event,
            kill_registry=kill_registry, cached_walk=True)
        self._counters = {"files_scanned": 0, "threats_found": 0}
        self._version = __version__
        self._state_lock = None  # single-threaded loop; no lock needed

    # ------------------------------------------------------------- helpers
    def _log(self, level: str, message: str) -> None:
        p = self._paths["log"]
        try:
            if p.exists() and p.stat().st_size > _MAX_LOG_SIZE:
                p.replace(p.with_name(LOG_FILE + ".1"))
            line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] " \
                   f"[{level}] {message}\n"
            with p.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass

    def _on_event(self, payload: Dict) -> None:
        event = payload.get("event")
        if event in ("clean", "threat"):
            self._counters["files_scanned"] += 1
        if event == "threat":
            self._counters["threats_found"] += 1
        payload = dict(payload)
        payload["files_scanned"] = self._counters["files_scanned"]
        payload["threats_found"] = self._counters["threats_found"]
        self._write_state(last_event=payload)

    def _write_state(self, last_event: Optional[Dict] = None) -> None:
        state = {
            "version": 1,
            "pid": os.getpid(),
            "version": self._version,
            "started_at": getattr(self, "_started_at", None),
            "stopped_at": getattr(self, "_stopped_at", None),
            "target": str(self.target),
            "action": self.action,
            "interval": self.interval,
            "initial_scan": self.initial,
            "files_scanned": self._counters["files_scanned"],
            "threats_found": self._counters["threats_found"],
            "last_event": last_event,
        }
        tmp = self._paths["state"].with_name(STATE_FILE + ".tmp")
        try:
            tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
            os.replace(tmp, self._paths["state"])
        except OSError:
            pass

    # --------------------------------------------------------------- main
    def run(self) -> int:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._paths["pid"].write_text(str(os.getpid()) + "\n")
        self._started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._write_state()
        self._log("info", f"guard started (pid {os.getpid()}, v{self._version})")
        self._log("info", f"watching {self.target} every {self.interval:g}s "
                          f"(action={self.action})")
        try:
            if self.initial:
                self._initial_scan()
            # First snapshot establishes the baseline (nothing scanned).
            self.watcher.poll(self.target)
            while True:
                time.sleep(self.interval)
                if self._paths["stop"].exists():
                    self._log("info", "stop requested — exiting")
                    break
                try:
                    changed, removed = self.watcher.poll(self.target)
                except OSError as exc:
                    self._log("error", f"poll failed: {exc}")
                    continue
                if changed or removed:
                    self.watcher.process((changed, removed))
        except KeyboardInterrupt:  # pragma: no cover
            pass
        finally:
            self._stopped_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._write_state()
            try:
                self._paths["pid"].unlink()
            except OSError:
                pass
            self._log("info", f"guard stopped "
                              f"({self._counters['files_scanned']} file(s) "
                              f"scanned, {self._counters['threats_found']} "
                              f"threat(s))")
        return 0

    def _initial_scan(self) -> None:
        from .api import apply_actions
        from .kill import KillRegistry
        from .quarantine import Quarantine

        try:
            result = self._scanner.scan_path(self.target)
            notes = apply_actions(
                result, Quarantine(self._config.quarantine_dir),
                self.action,
                kill_registry=KillRegistry(self._config.registry_dir))
            self._counters["files_scanned"] += result.files_scanned
            self._counters["threats_found"] += len(result.findings)
            self._write_state()
            self._log("info", f"initial scan: {result.files_scanned} file(s), "
                              f"{len(result.findings)} finding(s)")
            for note_path, note in notes.items():
                self._log("info", f"initial: {note_path} -> {note}")
        except OSError as exc:
            self._log("error", f"initial scan failed: {exc}")


# ------------------------------------------------------------------ control
#: Popen handles for daemons started from this process.  Kept so they are
#: reaped when they exit (no zombies, no ResourceWarnings); pruned lazily.
_KNOWN_PROCS: Dict[int, "subprocess.Popen"] = {}


def _register_proc(proc: "subprocess.Popen") -> None:
    for pid in [p for p, q in _KNOWN_PROCS.items() if q.poll() is not None]:
        _KNOWN_PROCS.pop(pid, None)
    _KNOWN_PROCS[proc.pid] = proc


def start_guard(target: str, action: str = "quarantine", interval: float = 5.0,
                initial: bool = False, state_dir: str = "guard",
                signatures: Optional[str] = None,
                wait: float = 10.0) -> Dict:
    """Spawn the detached guard daemon; returns its info (with ``pid``)."""
    state_dir = Path(state_dir)
    existing = guard_running(state_dir)
    if existing is not None:
        raise RuntimeError(f"a guard is already running (pid {existing}); "
                           f"stop it first (antivirus guard stop)")
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"no such file or directory: {target}")

    argv = [sys.executable, "-m", "antivirus", "guard", "_daemon",
            "--state-dir", str(state_dir), "--target", str(target_path),
            "--action", action, "--interval", str(interval)]
    if initial:
        argv.append("--initial")
    if signatures:
        argv += ["--signatures", str(signatures)]

    env = dict(os.environ)
    root = _package_root()
    if root:
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")

    _register_proc(subprocess.Popen(argv, env=env, **_spawn_kwargs()))

    deadline = time.time() + wait
    while time.time() < deadline:
        pid = guard_running(state_dir)
        if pid is not None:
            state = read_state(state_dir) or {}
            return {
                "pid": pid,
                "state_dir": str(state_dir),
                "target": state.get("target", str(target_path)),
                "action": state.get("action", action),
                "interval": state.get("interval", interval),
            }
        time.sleep(0.1)
    raise RuntimeError(
        f"guard did not announce itself within {wait:g}s "
        f"(state dir: {state_dir})")


def stop_guard(state_dir: str = "guard", timeout: float = 15.0) -> bool:
    """Ask the guard to stop (sentinel) and wait; force-kills if needed.

    Returns True when no guard is running afterwards.
    """
    p = _paths(Path(state_dir))
    pid = read_pid(state_dir)
    if pid is None or not pid_alive(pid):
        for f in (p["pid"], p["stop"]):
            try:
                f.unlink()
            except OSError:
                pass
        return True
    try:
        p["stop"].write_text(
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
    except OSError:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            break
        time.sleep(0.2)
    if pid_alive(pid):
        _force_kill(pid)
        for _ in range(25):
            if not pid_alive(pid):
                break
            time.sleep(0.1)
    for f in (p["pid"], p["stop"]):
        try:
            f.unlink()
        except OSError:
            pass
    # Reap it in this process if we spawned it here (clears the zombie).
    proc = _KNOWN_PROCS.pop(pid, None)
    if proc is not None:
        try:
            proc.poll()
        except Exception:
            pass
    return not pid_alive(pid)


# ------------------------------------------------------------------- runner
def run_daemon_cli(args) -> int:
    """Entry point for the hidden ``guard _daemon`` subcommand."""
    daemon = GuardDaemon(
        state_dir=Path(args.state_dir), target=Path(args.target),
        action=args.action, interval=args.interval,
        initial=args.initial, signatures=args.signatures)
    return daemon.run()
