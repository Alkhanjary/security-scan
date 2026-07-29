#!/usr/bin/env python3
"""
app_launcher.py

Auto-detects and starts a local web app from a folder, so `--web` has
something to scan when a folder has no live/deployed URL yet. Used by
scanner.py's main() when --web (or --all) is requested with no --url:
the folder that would otherwise just be code-scanned is also checked for
a runnable app, started locally, scanned, then torn down.

Detection covers the common cases across languages/frameworks, tried in
order from most to least specific: a Procfile, Django, FastAPI, Flask,
Node (npm/yarn/pnpm), Ruby (Rails/Rack), .NET, Java/Spring Boot (Maven or
Gradle), Go, PHP, a Makefile run/serve/start/dev target, Docker Compose, a
standalone Dockerfile, a generic Python entrypoint, a start/run/serve shell
script, or static HTML. Whatever it finds first is what runs; if nothing
matches, it fails with a clear error telling you to start the app yourself
and pass --url instead, rather than guessing wrong and running something
unintended.

Only launch and scan apps you own or are explicitly authorized to test —
the same rule as the rest of security-scan.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_up(urls, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for url in urls:
            try:
                requests.get(url, timeout=2)
                return url
            except requests.RequestException:
                continue
        time.sleep(0.5)
    return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _urls_for_ports(ports) -> list:
    return [f"http://127.0.0.1:{p}/" for p in sorted(set(ports))]


def _which(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


# Each detector inspects `folder` and returns (label, argv, env_overrides,
# candidate_urls), or None if its markers aren't present. Tried in order
# from most to least specific/unambiguous.

def _detect_django(folder: Path, port: int):
    if not (folder / "manage.py").exists():
        return None
    return (
        "Django (manage.py)",
        [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}"],
        {}, _urls_for_ports([port]),
    )


def _detect_flask(folder: Path, port: int):
    for entry_name in ("app.py", "wsgi.py", "main.py"):
        entry = folder / entry_name
        if entry.exists() and "flask" in _read_text(entry).lower():
            return (
                "Flask",
                [sys.executable, "-m", "flask", "run", "--port", str(port)],
                {"FLASK_APP": entry_name, "FLASK_RUN_PORT": str(port)},
                _urls_for_ports([port]),
            )
    return None


def _detect_fastapi(folder: Path, port: int):
    for entry_name in ("main.py", "app.py", "api.py"):
        entry = folder / entry_name
        if entry.exists() and "fastapi" in _read_text(entry).lower():
            module = entry_name[:-3]
            return (
                "FastAPI (uvicorn)",
                [sys.executable, "-m", "uvicorn", f"{module}:app", "--port", str(port)],
                {}, _urls_for_ports([port]),
            )
    return None


def _detect_generic_python(folder: Path, port: int):
    for entry_name in ("app.py", "server.py", "main.py", "run.py", "manage.py", "wsgi.py"):
        entry = folder / entry_name
        if entry.exists():
            return (
                f"Python entrypoint ({entry_name})",
                [sys.executable, entry_name],
                {"PORT": str(port), "FLASK_RUN_PORT": str(port)},
                # No framework identified, so no port guarantee — poll ours
                # plus the common defaults for Flask/Django/generic dev servers.
                _urls_for_ports([port, 5000, 8000, 8080]),
            )
    return None


def _detect_node(folder: Path, port: int):
    pkg_path = folder / "package.json"
    if not pkg_path.exists():
        return None
    try:
        pkg = json.loads(_read_text(pkg_path) or "{}")
    except ValueError:
        pkg = {}
    scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
    script_name = next((s for s in ("start", "dev", "serve") if s in scripts), None)
    if not script_name:
        return None
    for mgr, lock in (("npm", "package-lock.json"), ("yarn", "yarn.lock"), ("pnpm", "pnpm-lock.yaml")):
        if (folder / lock).exists() and _which(mgr):
            manager = mgr
            break
    else:
        manager = "npm"
    exe = f"{manager}.cmd" if os.name == "nt" else manager
    # Many Node dev servers respect $PORT, but plenty default to a fixed
    # port regardless (3000 CRA/Express/Next, 5173 Vite, 4200 Angular,
    # 8080 Vue CLI) — poll all of them rather than assume ours was honored.
    return (
        f"Node ({manager} run {script_name})",
        [exe, "run", script_name],
        {"PORT": str(port)},
        _urls_for_ports([port, 3000, 5173, 4200, 8080, 5000]),
    )


def _detect_ruby(folder: Path, port: int):
    if (folder / "config" / "environment.rb").exists() or (folder / "bin" / "rails").exists():
        return (
            "Ruby on Rails",
            ["bundle", "exec", "rails", "server", "-p", str(port), "-b", "127.0.0.1"],
            {}, _urls_for_ports([port]),
        )
    if (folder / "config.ru").exists():
        return (
            "Rack app (rackup)",
            ["bundle", "exec", "rackup", "-p", str(port), "-o", "127.0.0.1"],
            {}, _urls_for_ports([port]),
        )
    return None


def _detect_php(folder: Path, port: int):
    if not list(folder.glob("*.php")) and not (folder / "index.php").exists():
        return None
    return (
        "PHP built-in server",
        ["php", "-S", f"127.0.0.1:{port}"],
        {}, _urls_for_ports([port]),
    )


def _detect_go(folder: Path, port: int):
    if not (folder / "go.mod").exists():
        return None
    return (
        "Go (go run .)",
        ["go", "run", "."],
        {"PORT": str(port)},
        _urls_for_ports([port, 8080]),
    )


def _shell_argv(cmd: str):
    """argv for running a shell command line as a single process, per platform."""
    if os.name == "nt":
        return ["cmd", "/c", cmd]
    return ["sh", "-c", cmd]


def _detect_procfile(folder: Path, port: int):
    procfile = folder / "Procfile"
    if not procfile.exists():
        return None
    m = re.search(r"^web:\s*(.+)$", _read_text(procfile), re.MULTILINE)
    if not m:
        return None
    return (
        "Procfile (web process)",
        _shell_argv(m.group(1).strip()),
        {"PORT": str(port)}, _urls_for_ports([port, 5000, 8000, 3000]),
    )


def _detect_dotnet(folder: Path, port: int):
    if not list(folder.glob("*.csproj")) and not list(folder.glob("*.sln")):
        return None
    if not _which("dotnet"):
        return None
    return (
        ".NET (dotnet run)",
        ["dotnet", "run", "--urls", f"http://127.0.0.1:{port}"],
        {}, _urls_for_ports([port]),
    )


def _detect_java(folder: Path, port: int):
    has_maven = (folder / "pom.xml").exists()
    has_gradle = (folder / "build.gradle").exists() or (folder / "build.gradle.kts").exists()
    if not has_maven and not has_gradle:
        return None
    text = _read_text(folder / "pom.xml") + _read_text(folder / "build.gradle") + _read_text(folder / "build.gradle.kts")
    if "spring-boot" not in text.lower():
        return None  # only Spring Boot's run target is unambiguous enough to auto-start
    env = {"SERVER_PORT": str(port), "PORT": str(port)}
    if has_maven and _which("mvn"):
        return ("Java / Spring Boot (Maven)", ["mvn", "spring-boot:run"], env, _urls_for_ports([port, 8080]))
    if has_gradle:
        gradlew = "gradlew.bat" if os.name == "nt" else "./gradlew"
        exe = str(folder / gradlew) if (folder / gradlew).exists() else ("gradle" if _which("gradle") else None)
        if exe:
            return ("Java / Spring Boot (Gradle)", [exe, "bootRun"], env, _urls_for_ports([port, 8080]))
    return None


def _detect_makefile(folder: Path, port: int):
    makefile = next((folder / n for n in ("Makefile", "makefile") if (folder / n).exists()), None)
    if makefile is None or not _which("make"):
        return None
    targets = re.findall(r"^([a-zA-Z][\w-]*)\s*:", _read_text(makefile), re.MULTILINE)
    target = next((t for t in ("run", "serve", "start", "dev") if t in targets), None)
    if not target:
        return None
    return (
        f"Makefile (make {target})",
        ["make", target],
        {"PORT": str(port)}, _urls_for_ports([port, 8080, 3000, 5000, 8000]),
    )


def _detect_dockerfile(folder: Path, port: int):
    dockerfile = folder / "Dockerfile"
    if not dockerfile.exists() or not _which("docker"):
        return None
    exposed = [int(m) for m in re.findall(r"(?im)^\s*EXPOSE\s+(\d{2,5})", _read_text(dockerfile))]
    container_port = exposed[0] if exposed else port
    tag = f"security-scan-tmp-{os.getpid()}"
    build_and_run = (
        f"docker build -t {tag} . && "
        f"docker run --rm -d -p {port}:{container_port} --name {tag} {tag}"
    )
    return (
        "Dockerfile (docker build + run)",
        _shell_argv(build_and_run),
        {},
        # Building an image can take a while; the caller's launch timeout
        # needs to be generous for this one.
        _urls_for_ports([port]),
        # `-d` detaches immediately, so killing this process's tree does
        # nothing to the container — stop it by name on cleanup instead.
        ["docker", "stop", tag],
    )


def _detect_shell_script(folder: Path, port: int):
    script = next((folder / n for n in ("start.sh", "run.sh", "serve.sh") if (folder / n).exists()), None)
    if script is None:
        return None
    runner = "bash" if _which("bash") else ("sh" if _which("sh") else None)
    if runner is None:
        return None
    return (
        f"Shell script ({script.name})",
        [runner, script.name],
        {"PORT": str(port)}, _urls_for_ports([port, 8080, 3000, 5000, 8000]),
    )


def _detect_docker_compose(folder: Path, port: int):
    compose_file = next(
        (folder / n for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
         if (folder / n).exists()),
        None,
    )
    if compose_file is None or not _which("docker"):
        return None
    ports = [int(m) for m in re.findall(r'"?(\d{2,5}):\d{2,5}"?', _read_text(compose_file))]
    return (
        f"Docker Compose ({compose_file.name})",
        ["docker", "compose", "-f", compose_file.name, "up", "-d"],
        {}, _urls_for_ports(ports or [port, 8080, 3000, 80]),
        # `up -d` detaches immediately, so killing this process's tree does
        # nothing to the containers it started — they need an explicit
        # `down` on cleanup instead.
        ["docker", "compose", "-f", compose_file.name, "down"],
    )


def _detect_static_html(folder: Path, port: int):
    if not (folder / "index.html").exists() and not list(folder.glob("*.html")):
        return None
    return (
        "Static site (http.server)",
        [sys.executable, "-m", "http.server", str(port)],
        {}, _urls_for_ports([port]),
    )


_DETECTORS = [
    _detect_procfile,
    _detect_django,
    _detect_fastapi,
    _detect_flask,
    _detect_node,
    _detect_ruby,
    _detect_dotnet,
    _detect_java,
    _detect_go,
    _detect_php,
    _detect_makefile,
    _detect_docker_compose,
    _detect_dockerfile,
    _detect_generic_python,
    _detect_shell_script,
    _detect_static_html,
]


def detect_start_plan(folder: Path, port: int):
    """Returns (label, argv, env_overrides, candidate_urls, cleanup_argv),
    or None if nothing recognized was found in `folder`. cleanup_argv is
    None for anything that stops when its process tree is killed; it's only
    set for detectors (Docker Compose, standalone Dockerfile) whose `-d`
    flag detaches the real process, so tearing it down needs an explicit
    command instead."""
    for detector in _DETECTORS:
        plan = detector(folder, port)
        if plan:
            return plan if len(plan) == 5 else (*plan, None)
    return None


class LaunchedApp:
    def __init__(self, process, url, label, cleanup_argv=None, cwd=None):
        self.process = process
        self.url = url
        self.label = label
        self.cleanup_argv = cleanup_argv
        self.cwd = cwd

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            try:
                if os.name == "nt":
                    # npm/flask/django dev servers commonly spawn child
                    # processes; plain terminate() on the parent alone
                    # leaves those running on Windows, so kill the whole
                    # tree instead.
                    subprocess.run(
                        ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                        capture_output=True,
                    )
                else:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
            except Exception:
                pass

        # Docker Compose / standalone Dockerfile detach immediately (`-d`),
        # so the process above has usually already exited on its own — the
        # actual container(s) need this explicit teardown command instead.
        if self.cleanup_argv:
            try:
                subprocess.run(self.cleanup_argv, cwd=self.cwd, capture_output=True, timeout=30)
            except Exception:
                pass


def launch_app(folder: Path, timeout: float = 25.0, show_progress: bool = True):
    """Detects and starts a local app in `folder`. Returns
    (LaunchedApp, None) on success — call .stop() on it once you're done
    scanning — or (None, error_message) if nothing was detected, the
    process failed to start, or it never became reachable in time."""
    plan = detect_start_plan(folder, _free_port())
    if plan is None:
        return None, (
            f"Couldn't detect a runnable app in '{folder}' (looked for a Procfile, Django, FastAPI, "
            f"Flask, Node (package.json), Ruby (Rails/Rack), .NET, Java/Spring Boot, Go, PHP, a "
            f"Makefile run/serve/start/dev target, Docker Compose, a Dockerfile, a generic Python "
            f"entrypoint, a start/run/serve shell script, or static HTML). Start it yourself and "
            f"pass --url instead."
        )

    label, argv, env_overrides, candidate_urls, cleanup_argv = plan
    if show_progress:
        print(f"[*] Detected {label} in '{folder}' — starting: {' '.join(argv)}", flush=True)

    env = os.environ.copy()
    env.update(env_overrides)
    try:
        process = subprocess.Popen(
            argv, cwd=str(folder), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        return None, f"Failed to start {label}: {e}"

    # Building a Docker image can genuinely take a couple of minutes; give
    # that detector more room than the default before giving up.
    effective_timeout = max(timeout, 120.0) if "Dockerfile" in label else timeout
    up_url = _wait_for_up(candidate_urls, effective_timeout)
    if not up_url:
        LaunchedApp(process, None, label, cleanup_argv, cwd=str(folder)).stop()
        return None, (
            f"Started {label} but it never responded on {', '.join(candidate_urls)} "
            f"within {effective_timeout:.0f}s. It may need dependencies installed first "
            f"(e.g. npm install / pip install -r requirements.txt), or use a port "
            f"this scan didn't check — start it yourself and pass --url instead."
        )

    if show_progress:
        print(f"[*] {label} is up at {up_url}", flush=True)
    return LaunchedApp(process, up_url, label, cleanup_argv, cwd=str(folder)), None
