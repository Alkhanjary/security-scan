"""Background scan orchestration for the web UI.

Runs scanner.py as a subprocess (`sys.executable scanner.py <target> --json
<tmp> --scan <types> ...`) exactly like a CLI user would, rather than calling
scan_target()/scan_url()/scan_network() in-process. That gets three things
for free: live log output identical to the CLI's own, trivial cancellation
(terminate the subprocess) instead of threading cancel-checks through the
scan loops, and a crashing/hanging scan can't take the web server down with
it. Report generation (once a report.json exists) runs in-process since it's
fast and pure.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent
SCANNER_PATH = REPO_ROOT / "scanner.py"
DATA_DIR = WEB_DIR / "data"
HISTORY_FILE = DATA_DIR / "scan_history.json"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

JOBS = {}
_jobs_lock = threading.Lock()
_history_lock = threading.Lock()


# --------------------------------------------------------------- utilities
# Rule names are owned by web_scan.py / network_scan.py, so membership is an
# exact answer rather than a guess. Imported at call time to keep this module
# importable even if a scanner module is missing.
def _rule_sets():
    web, network = set(), set()
    try:
        from web_scan import SEVERITY as WEB_SEVERITY
        web = set(WEB_SEVERITY)
    except Exception:
        pass
    try:
        from network_scan import SEVERITY as NET_SEVERITY
        network = set(NET_SEVERITY)
    except Exception:
        pass
    return web, network


def classify_scan_type(finding: dict) -> str:
    """Which scan produced this finding — the merged report doesn't say.

    Decided by rule name first, because that is authoritative: network
    findings reuse `file` for the host and `line` for the port (see
    network_scan._add), so a "host:port" shape never actually appears in
    `file` and matching on it silently labelled every network finding as
    code. The shape checks below are only a fallback for AI-discovered
    findings, which carry rule names the deterministic tables don't know.
    """
    rule = str(finding.get("rule") or "")
    web_rules, network_rules = _rule_sets()
    if rule in network_rules:
        return "network"
    if rule in web_rules:
        return "web"

    file_field = str(finding.get("file") or "")
    if file_field.startswith("http://") or file_field.startswith("https://"):
        return "web"
    if re.match(r"^[\w.\-]+:\d+$", file_field):
        return "network"
    return "code"


def _is_self_artifact(file_field: str) -> bool:
    """Findings inside this tool's own output/state aren't application code
    — scanning security-scan's own folder would otherwise re-report the
    contents of past report.json/report.md files and this app's own scan
    history as if they were fresh vulnerabilities."""
    norm = str(file_field or "").replace("\\", "/").lstrip("./")
    if norm in ("report.json", "report.md"):
        return True
    if norm.startswith("web/data/"):
        return True
    return False


def _is_dismissed(f: dict, include_test_files: bool = False) -> bool:
    """Whether a finding is set aside rather than actionable.

    Mirrors scanner.py's own policy: an explicit AI verdict wins either way,
    and failing that, a finding sitting in a test/fixture file is set aside
    unless the caller asked for those to count — a hardcoded password in a
    fixture is usually the project's own sample data, not a leak."""
    if f.get("ai_verdict") == "false_positive":
        return True
    if f.get("ai_verdict") == "true_positive":
        return False
    return bool(f.get("likely_test_fixture")) and not include_test_files


def count_scannable_files(target: Path) -> int:
    """How many files scanner.py's code scan will actually walk.

    Its own progress output ("[regex N] <file>") counts up but never states a
    total, so the UI can't show a percentage without one. Mirrors
    scan_target()'s traversal — same SKIP_DIRS and MAX_DEPTH, counting every
    file handed to _scan_file (including ones it later skips, since those
    still advance the counter)."""
    try:
        from scanner import SKIP_DIRS, MAX_DEPTH
    except ImportError:
        return 0
    if target.is_file():
        return 1
    total = 0
    try:
        for root, dirs, files in os.walk(target, followlinks=False):
            root_path = Path(root)
            try:
                depth = len(root_path.relative_to(target).parts)
            except ValueError:
                continue
            if depth >= MAX_DEPTH:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            total += len(files)
    except OSError:
        pass
    return total


def _strip_ansi(line: str) -> str:
    return _ANSI_RE.sub("", line)


def normalize_url(url: str) -> str:
    """Adds a scheme when the user typed a bare host.

    Everything downstream parses this with urlparse, which only reports a
    hostname when a scheme is present — "google.com" parses entirely as a
    path. Defaulting to https rather than http so the scan doesn't quietly
    downgrade a site that supports TLS.
    """
    url = (url or "").strip()
    if not url:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        return url
    return "https://" + url.lstrip("/")


# ------------------------------------------------------------------ upload
class UploadError(ValueError):
    pass


def materialize_upload(files: list) -> Path:
    """Writes browser-uploaded files (webkitdirectory) into a fresh temp
    dir. `files` is a list of {"path": "<relative path>", "content": "<text>"}.
    Every destination is resolved and checked to still be inside the upload
    root before writing — a relative path from the client could otherwise
    climb out of the temp dir with '../..' (or, on Windows, an absolute
    'C:/...' entry replacing the base entirely)."""
    upload_dir = Path(tempfile.mkdtemp(prefix="ss-upload-"))
    upload_root = upload_dir.resolve()
    written = 0
    for f in files:
        rel_path = (f.get("path") or "").lstrip("/\\")
        if not rel_path:
            continue
        dest = upload_dir / rel_path
        try:
            resolved = dest.resolve()
            resolved.relative_to(upload_root)
        except (ValueError, OSError):
            continue
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(f.get("content") or "", encoding="utf-8", errors="replace")
        written += 1
    if written == 0:
        raise UploadError("No usable files were uploaded.")
    return upload_dir


# -------------------------------------------------------------------- jobs
MAX_FINISHED_JOBS = 20


def _prune_jobs():
    """Jobs hold their full log and result in memory. Every scan is also
    persisted to history, so finished ones only need to stick around long
    enough for the client polling them to collect the result."""
    with _jobs_lock:
        finished = [(jid, j) for jid, j in JOBS.items() if j["status"] != "running"]
        if len(finished) <= MAX_FINISHED_JOBS:
            return
        finished.sort(key=lambda pair: pair[1]["started"])
        for jid, _ in finished[:len(finished) - MAX_FINISHED_JOBS]:
            JOBS.pop(jid, None)


def start_job(params: dict) -> str:
    """params: scan_types(list), local_path(str|None), files(list|None),
    url, net_target, net_ports, ai(bool), include_test_files(bool), fail_on,
    auto_build(bool)."""
    scan_types = params.get("scan_types") or ["code"]
    local_path = (params.get("local_path") or "").strip()
    files = params.get("files")

    if "code" in scan_types and not local_path and not files:
        raise UploadError("Code scan needs a source: a local folder path or an uploaded folder.")
    if params.get("auto_build") and not local_path and not files:
        raise UploadError("Auto-build needs a source folder to build from.")

    if local_path:
        p = Path(local_path).expanduser()
        try:
            p = p.resolve(strict=True)
        except (OSError, RuntimeError):
            raise UploadError(f"That folder does not exist: {local_path}")
        if not p.is_dir():
            raise UploadError(f"Not a folder: {p}")

    _prune_jobs()
    job_id = str(uuid.uuid4())
    target_label = local_path or ("(uploaded folder)" if files else "")
    if not target_label:
        target_label = params.get("url") or params.get("net_target") or "(no source)"

    with _jobs_lock:
        JOBS[job_id] = {
            "status": "running",
            "log": [],
            "result": None,
            "error": None,
            "started": time.time(),
            "target": target_label,
            "scan_types": scan_types,
            "cancel_requested": False,
            "proc": None,
            "record_id": None,
        }

    thread = threading.Thread(target=_run_job, args=(job_id, params), daemon=True)
    thread.start()
    return job_id


def _run_job(job_id: str, params: dict):
    job = JOBS[job_id]
    built_process = None
    try:
        scan_types = params.get("scan_types") or ["code"]
        local_path = (params.get("local_path") or "").strip()
        files = params.get("files")
        url = normalize_url(params.get("url")) or None
        net_target = (params.get("net_target") or "").strip() or None
        net_ports = (params.get("net_ports") or "").strip() or None
        try:
            web_max_pages = max(1, min(int(params.get("web_max_pages") or 25), 2000))
        except (TypeError, ValueError):
            web_max_pages = 25
        auto_build = bool(params.get("auto_build"))
        use_ai = bool(params.get("ai"))
        include_test_files = bool(params.get("include_test_files"))
        # Default "none": the dashboard is for reading findings, not gating a
        # build, so a scan reports results rather than a pass/fail verdict
        # unless a threshold is explicitly chosen.
        fail_on = params.get("fail_on") or "none"

        target_dir = None
        if local_path:
            target_dir = Path(local_path).expanduser().resolve()
            job["log"].append(f"Scanning folder in place (no upload): {target_dir}")
        elif files:
            target_dir = materialize_upload(files)
            job["log"].append(f"Uploaded folder staged at: {target_dir}")

        # Emit the total the scanner itself never prints, so the UI can turn
        # its per-file "[regex N]" lines into a real percentage.
        if "code" in scan_types and target_dir:
            job["log"].append(f"[[progress-total]] {count_scannable_files(target_dir)}")

        if auto_build and "web" in scan_types and not url and target_dir:
            from app_launcher import launch_app
            job["log"].append(f"Auto-build: looking for a local app to launch in '{target_dir}' ...")
            launched, launch_error = launch_app(target_dir, show_progress=False)
            if launched:
                url = launched.url
                built_process = launched
                job["log"].append(f"Auto-build: launched {launched.label} at {url}")
            else:
                job["status"] = "error"
                job["error"] = f"Auto-build failed: {launch_error}"
                return

        tmpdir = tempfile.mkdtemp(prefix="ss-job-")
        json_out = str(Path(tmpdir) / "report.json")
        scan_arg = ",".join(scan_types)
        cmd = [sys.executable, str(SCANNER_PATH)]
        if target_dir:
            cmd.append(str(target_dir))
        cmd += ["--json", json_out, "--scan", scan_arg, "--fail-on", fail_on]
        if use_ai:
            cmd.append("--ai")
        if include_test_files:
            cmd.append("--include-test-files")
        if url:
            cmd += ["--url", url]
        if net_target:
            cmd += ["--net-target", net_target]
        if net_ports:
            cmd += ["--net-ports", net_ports]
        if web_max_pages:
            cmd += ["--web-max-pages", str(web_max_pages)]

        job["log"].append("Starting scan: " + " ".join(cmd))

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, encoding="utf-8", errors="replace", env=env,
        )
        job["proc"] = proc
        for line in proc.stdout:
            line = _strip_ansi(line.rstrip())
            if line:
                job["log"].append(line)
        proc.wait()
        job["proc"] = None

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["log"].append("Scan cancelled.")
            return

        try:
            with open(json_out, "r", encoding="utf-8") as fh:
                report = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            job["status"] = "error"
            job["error"] = "Scanner did not produce a valid report (see log)."
            return

        raw_findings = report.get("findings") or []
        kept = [f for f in raw_findings if not _is_self_artifact(f.get("file"))]
        if len(kept) != len(raw_findings):
            job["log"].append(
                f"Ignored {len(raw_findings) - len(kept)} finding(s) inside this tool's own "
                "report/history output (not application code).")
        for f in kept:
            f["scan_type"] = classify_scan_type(f)
        report["findings"] = kept
        report["ai_used"] = use_ai
        report["fail_on"] = fail_on
        report["include_test_files"] = include_test_files

        display_target = target_label_for(target_dir, url, net_target)
        record = save_scan_record(display_target, scan_types, report)

        job["status"] = "done"
        job["result"] = report
        job["record_id"] = record["id"]
        real = len([f for f in kept if not _is_dismissed(f)])
        job["log"].append(f"Scan findings saved: {len(kept)} total ({real} actionable). History: {record['id']}")
    except Exception as e:  # noqa: BLE001 - surface any failure to the UI instead of a dead job
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        if built_process:
            try:
                job["log"].append(f"Stopping locally-launched {built_process.label} ...")
                built_process.stop()
            except Exception:
                pass


def target_label_for(target_dir, url, net_target) -> str:
    parts = []
    if target_dir:
        parts.append(str(target_dir))
    if url:
        parts.append(url)
    if net_target:
        parts.append(net_target)
    return ", ".join(parts) if parts else "(no source)"


def get_status(job_id: str, since: int = 0):
    job = JOBS.get(job_id)
    if not job:
        return None
    log = job["log"]
    since = max(0, since)
    start = min(since, len(log))
    delta = log[start:]
    return {
        "status": job["status"],
        "log": delta,
        "log_total": len(log),
        "result": job["result"],
        "error": job["error"],
        "record_id": job["record_id"],
        "elapsed": round(time.time() - job["started"], 1),
    }


def cancel_job(job_id: str) -> bool:
    job = JOBS.get(job_id)
    if not job or job["status"] != "running":
        return False
    job["cancel_requested"] = True
    proc = job.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
    return True


# --------------------------------------------------------------- history
class HistoryCorrupt(RuntimeError):
    """The history file exists but could not be parsed."""


def _load_history() -> list:
    """Raises HistoryCorrupt rather than returning [] when the file exists
    but won't parse.

    Returning an empty list on a parse failure looks harmless but is not:
    save_scan_record loads, appends and writes back, so one unreadable file
    turns the next scan into a silent wipe of every record before it.
    Callers that write must let this propagate; read-only callers can catch
    it and show nothing.
    """
    if not HISTORY_FILE.exists():
        return []
    try:
        raw = HISTORY_FILE.read_text(encoding="utf-8")
    except OSError as e:
        raise HistoryCorrupt(f"Could not read scan history: {e}")
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HistoryCorrupt(f"Scan history is not valid JSON: {e}")
    if not isinstance(data, list):
        raise HistoryCorrupt("Scan history file is not a list of records.")
    return data


def _load_history_safe() -> list:
    """For read-only paths: a corrupt file means 'nothing to show', not a 500."""
    try:
        return _load_history()
    except HistoryCorrupt:
        return []


def _save_history(records: list):
    """Writes atomically.

    A direct write to the real path leaves a truncated file if the process
    dies mid-write — which then fails to parse, which (before this) wiped
    the history. Writing a temp file in the same directory and renaming it
    means readers only ever see a complete file.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".scan_history-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, HISTORY_FILE)   # atomic on POSIX and Windows
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _finding_keys(findings: list) -> set:
    return {
        (f.get("rule"), f.get("file"), f.get("line"))
        for f in findings if not _is_dismissed(f)
    }


def save_scan_record(target: str, scan_types: list, report: dict, name: str = "") -> dict:
    with _history_lock:
        records = _load_history()
        prev = next((r for r in reversed(records) if r.get("target") == target), None)
        record = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "name": name,
            "target": target,
            "scan_types": scan_types,
            "files_scanned": report.get("files_scanned", 0),
            "findings": report.get("findings", []),
            "exit_code": report.get("exit_code"),
            "fail_on": report.get("fail_on", "none"),
            "include_test_files": report.get("include_test_files", False),
            "ai_used": report.get("ai_used", False),
            "ai_risk_summary": report.get("ai_risk_summary"),
            "ai_recommendations": report.get("ai_recommendations"),
        }
        if prev:
            prev_keys = _finding_keys(prev["findings"])
            curr_keys = _finding_keys(record["findings"])
            record["history_delta"] = {
                "new": len(curr_keys - prev_keys),
                "fixed": len(prev_keys - curr_keys),
            }
        else:
            record["history_delta"] = None
        records.append(record)
        _save_history(records)
        return record


def severity_counts(findings: list, include_test_files: bool = False) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if _is_dismissed(f, include_test_files):
            continue
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def list_history(limit: int = 25, offset: int = 0) -> dict:
    with _history_lock:
        records = _load_history_safe()
    items = []
    for rec in reversed(records):
        inc = rec.get("include_test_files", False)
        items.append({
            "id": rec["id"],
            "name": rec.get("name", ""),
            "target": rec.get("target", ""),
            "timestamp": rec.get("timestamp", 0),
            "scan_types": rec.get("scan_types", []),
            "files_scanned": rec.get("files_scanned", 0),
            "counts": severity_counts(rec.get("findings", []), inc),
            "total_findings": len([f for f in rec.get("findings", []) if not _is_dismissed(f, inc)]),
            "history_delta": rec.get("history_delta"),
            "ai_used": rec.get("ai_used", False),
        })
    total = len(items)
    page = items[offset:offset + limit]
    return {"items": page, "total": total, "has_more": offset + limit < total}


def get_record(record_id: str):
    with _history_lock:
        records = _load_history_safe()
    return next((r for r in records if r["id"] == record_id), None)


def rename_record(record_id: str, name: str) -> bool:
    with _history_lock:
        records = _load_history()
        for r in records:
            if r["id"] == record_id:
                r["name"] = name
                _save_history(records)
                return True
    return False


def delete_record(record_id: str) -> bool:
    with _history_lock:
        records = _load_history()
        remaining = [r for r in records if r["id"] != record_id]
        if len(remaining) == len(records):
            return False
        _save_history(remaining)
        return True


def compare_records(id_a: str, id_b: str):
    rec_a, rec_b = get_record(id_a), get_record(id_b)
    if not rec_a or not rec_b:
        return None

    def keyed(rec):
        inc = rec.get("include_test_files", False)
        return {
            (f.get("rule"), f.get("file"), f.get("line")): f
            for f in rec["findings"] if not _is_dismissed(f, inc)
        }

    a_map, b_map = keyed(rec_a), keyed(rec_b)
    new = [b_map[k] for k in b_map.keys() - a_map.keys()]
    fixed = [a_map[k] for k in a_map.keys() - b_map.keys()]
    persisting = [b_map[k] for k in a_map.keys() & b_map.keys()]
    return {
        "a": {"id": rec_a["id"], "name": rec_a.get("name") or rec_a["target"], "timestamp": rec_a["timestamp"]},
        "b": {"id": rec_b["id"], "name": rec_b.get("name") or rec_b["target"], "timestamp": rec_b["timestamp"]},
        "new": new,
        "fixed": fixed,
        "persisting": persisting,
    }
