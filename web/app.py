"""Flask web UI for security-scan.

Serves the marketing landing page and the scan/history dashboard. Deliberately
binds to 127.0.0.1 only — this wraps a tool that launches local processes,
reads arbitrary local folders, and scans arbitrary web/network targets, so it
is a single-user local tool, the same as the CLI it wraps, not a public
service.
"""
import os
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent

# scanner.py / web_scan.py / network_scan.py / app_launcher.py live one
# level up, as plain scripts (not an installed package) — put the repo root
# on sys.path so modules under web/ can `import scanner` etc.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import reports  # noqa: E402
import scan_jobs  # noqa: E402

app = Flask(__name__)
# Pick up template edits without a restart. Unlike debug=True this enables
# neither the Werkzeug debugger (an arbitrary-code console) nor the
# file-watching reloader (which a scan trips by reading the repo's files).
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def set_security_headers(response):
    """Send the headers this tool's own web scan looks for.

    Pointing the scanner at this dashboard used to report missing CSP,
    X-Frame-Options, Referrer-Policy and friends — a security tool has no
    business shipping the very gaps it flags. The CSP is strict because the
    app needs nothing external: no CDN, no inline event handlers, and the
    only inline script is the pre-paint theme setter, which is why
    'unsafe-inline' is scoped to script-src rather than granted globally.
    """
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), interest-cohort=()")
    # Scan results are read from local state, never a shared cache.
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# --------------------------------------------------------------- pages
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/app")
def dashboard():
    return render_template("dashboard.html")


# ------------------------------------------------------------- scan API
@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    data = request.get_json(force=True, silent=True) or {}
    try:
        job_id = scan_jobs.start_job(data)
    except scan_jobs.UploadError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"job_id": job_id})


@app.route("/api/scan/status/<job_id>")
def scan_status(job_id):
    try:
        since = max(0, int(request.args.get("since", 0)))
    except (TypeError, ValueError):
        since = 0
    status = scan_jobs.get_status(job_id, since)
    if status is None:
        return jsonify({"error": "Unknown job_id — the server may have restarted. Check History instead."}), 404
    return jsonify(status)


@app.route("/api/scan/cancel/<job_id>", methods=["POST"])
def scan_cancel(job_id):
    if not scan_jobs.cancel_job(job_id):
        return jsonify({"error": "Scan is not running (or unknown job_id)."}), 400
    return jsonify({"status": "ok"})


# ---------------------------------------------------------- history API
@app.route("/api/scan/history")
def scan_history():
    try:
        limit = min(max(int(request.args.get("limit", 25)), 1), 200)
    except (TypeError, ValueError):
        limit = 25
    try:
        offset = max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        offset = 0
    return jsonify(scan_jobs.list_history(limit=limit, offset=offset))


@app.route("/api/scan/history/<record_id>", methods=["GET"])
def scan_history_detail(record_id):
    record = scan_jobs.get_record(record_id)
    if not record:
        return jsonify({"error": "Unknown scan id."}), 404
    return jsonify(record)


@app.route("/api/scan/history/<record_id>", methods=["PATCH"])
def scan_history_rename(record_id):
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()[:200]
    try:
        ok = scan_jobs.rename_record(record_id, name)
    except scan_jobs.HistoryCorrupt as e:
        return jsonify({"error": str(e)}), 500
    if not ok:
        return jsonify({"error": "Unknown scan id."}), 404
    return jsonify({"status": "ok"})


@app.route("/api/scan/history/<record_id>", methods=["DELETE"])
def scan_history_delete(record_id):
    try:
        ok = scan_jobs.delete_record(record_id)
    except scan_jobs.HistoryCorrupt as e:
        return jsonify({"error": str(e)}), 500
    if not ok:
        return jsonify({"error": "Unknown scan id."}), 404
    return jsonify({"status": "ok"})


@app.route("/api/scan/compare", methods=["POST"])
def scan_compare():
    data = request.get_json(force=True, silent=True) or {}
    result = scan_jobs.compare_records(data.get("a"), data.get("b"))
    if result is None:
        return jsonify({"error": "One or both scan ids were not found."}), 404
    return jsonify(result)


# ----------------------------------------------------------- report API
_REPORT_FORMATS = {
    # format: (label, extension, mimetype)
    "html":     ("HTML",     "html",  "text/html; charset=utf-8"),
    "pdf":      ("PDF",      "pdf",   "application/pdf"),
    "docx":     ("Word",     "docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xlsx":     ("Excel",    "xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "markdown": ("Markdown", "md",    "text/markdown; charset=utf-8"),
    "csv":      ("CSV",      "csv",   "text/csv; charset=utf-8"),
    "json":     ("JSON",     "json",  "application/json; charset=utf-8"),
    "sarif":    ("SARIF",    "sarif", "application/json; charset=utf-8"),
}


@app.route("/api/scan/formats")
def scan_formats():
    """Which export formats this install can actually produce — PDF/DOCX/XLSX
    depend on optional libraries, so the UI asks rather than offering a button
    that would download an error."""
    out = []
    for fmt, (label, ext, _mime) in _REPORT_FORMATS.items():
        available, reason = True, None
        if fmt in ("pdf", "docx", "xlsx"):
            module = {"pdf": "reportlab", "docx": "docx", "xlsx": "openpyxl"}[fmt]
            try:
                __import__(module)
            except ImportError:
                available, reason = False, f"needs the '{module}' package"
        out.append({"format": fmt, "label": label, "ext": ext,
                     "available": available, "reason": reason})
    return jsonify({"formats": out})


@app.route("/api/scan/report/<record_id>")
def scan_report(record_id):
    fmt = (request.args.get("format") or "markdown").lower()
    if fmt not in _REPORT_FORMATS:
        return jsonify({"error": f"Unknown format: {fmt}"}), 400
    record = scan_jobs.get_record(record_id)
    if not record:
        return jsonify({"error": "Unknown scan id."}), 404

    label, ext, mime = _REPORT_FORMATS[fmt]
    try:
        if fmt == "markdown":
            body = reports.build_markdown(record)
        elif fmt == "json":
            body = reports.build_json(record)
        elif fmt == "csv":
            body = reports.build_csv(record)
        elif fmt == "sarif":
            body = reports.build_sarif(record)
        elif fmt == "pdf":
            body = reports.build_pdf(record)
        elif fmt == "docx":
            body = reports.build_docx(record)
        elif fmt == "xlsx":
            body = reports.build_xlsx(record)
        else:
            scanned_at = datetime.fromtimestamp(record.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            body = render_template(
                "report_export.html",
                record=record,
                scanned_at=scanned_at,
                counts=scan_jobs.severity_counts(
                    record.get("findings", []), record.get("include_test_files", False)),
            )
    except reports.ExportUnavailable as e:
        return jsonify({"error": str(e)}), 501

    filename = f"security-scan-report.{ext}"
    return Response(
        body,
        mimetype=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ------------------------------------------------------------- browse API
_PROJECT_MARKERS = ("package.json", "pyproject.toml", "requirements.txt",
                     "docker-compose.yml", "setup.py", "go.mod", "Cargo.toml", ".git")


@app.route("/api/browse")
def browse_folders():
    """Lists subdirectories of a path so the dashboard can offer a folder
    picker. Directory names only, never file contents — and this server only
    ever binds to loopback, so this doesn't widen what's reachable beyond
    what the local user running it can already open in a file manager."""
    raw = (request.args.get("path") or "").strip()

    if not raw:
        home = Path.home()
        shortcuts = []
        for label, p in (("Home", home), ("Desktop", home / "Desktop"),
                          ("Documents", home / "Documents"), ("Downloads", home / "Downloads")):
            if p.is_dir():
                shortcuts.append({"name": label, "path": str(p)})
        if os.name == "nt":
            for letter in "CDEFGH":
                drive = Path(f"{letter}:\\")
                if drive.exists():
                    shortcuts.append({"name": f"{letter}: drive", "path": str(drive)})
        else:
            shortcuts.append({"name": "/", "path": "/"})
        return jsonify({"path": None, "parent": None, "shortcuts": shortcuts, "entries": []})

    try:
        current = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return jsonify({"error": f"No such folder: {raw}"}), 400
    if not current.is_dir():
        return jsonify({"error": f"Not a folder: {current}"}), 400

    entries = []
    try:
        for child in sorted(current.iterdir(), key=lambda p: p.name.lower()):
            try:
                if not child.is_dir():
                    continue
            except OSError:
                continue
            if child.name.startswith(("$", ".")) and child.name not in (".github",):
                continue
            is_project = False
            try:
                is_project = any((child / m).exists() for m in _PROJECT_MARKERS)
            except OSError:
                pass
            entries.append({"name": child.name, "path": str(child), "is_project": is_project})
    except PermissionError:
        pass

    parent = str(current.parent) if current.parent != current else None
    return jsonify({"path": str(current), "parent": parent, "entries": entries})


if __name__ == "__main__":
    # Werkzeug writes its own Server header at the WSGI layer, below Flask's
    # response object — setting response.headers["Server"] appends a second
    # one rather than replacing it, leaving the exact Werkzeug and Python
    # versions on the wire. Override it at the layer that actually emits it.
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "security-scan"
    WSGIRequestHandler.sys_version = ""

    port = int(os.environ.get("PORT", 5057))
    # debug=False deliberately: the Werkzeug debugger is an arbitrary-code
    # console, and the auto-reloader watches the whole repo tree — a scan
    # reading those files trips it and restarts the server mid-job.
    print(f" * security-scan web UI on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
