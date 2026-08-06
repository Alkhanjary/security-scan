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
def classify_scan_type(finding: dict) -> str:
    """The merged scan report doesn't tag each finding with which scan type
    produced it, so infer one from the shape of `file`: a URL means the web
    scan, a bare host:port means the network scan, anything else is a real
    source file (code)."""
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


def _is_dismissed(f: dict) -> bool:
    return f.get("ai_verdict") == "false_positive"


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
        url = (params.get("url") or "").strip() or None
        net_target = (params.get("net_target") or "").strip() or None
        net_ports = (params.get("net_ports") or "").strip() or None
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
def _load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_history(records: list):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(records, indent=2), encoding="utf-8")


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


def severity_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if _is_dismissed(f):
            continue
        sev = (f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def list_history(limit: int = 25, offset: int = 0) -> dict:
    with _history_lock:
        records = _load_history()
    items = []
    for rec in reversed(records):
        items.append({
            "id": rec["id"],
            "name": rec.get("name", ""),
            "target": rec.get("target", ""),
            "timestamp": rec.get("timestamp", 0),
            "scan_types": rec.get("scan_types", []),
            "files_scanned": rec.get("files_scanned", 0),
            "counts": severity_counts(rec.get("findings", [])),
            "total_findings": len([f for f in rec.get("findings", []) if not _is_dismissed(f)]),
            "history_delta": rec.get("history_delta"),
            "ai_used": rec.get("ai_used", False),
        })
    total = len(items)
    page = items[offset:offset + limit]
    return {"items": page, "total": total, "has_more": offset + limit < total}


def get_record(record_id: str):
    with _history_lock:
        records = _load_history()
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
        return {
            (f.get("rule"), f.get("file"), f.get("line")): f
            for f in rec["findings"] if not _is_dismissed(f)
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
