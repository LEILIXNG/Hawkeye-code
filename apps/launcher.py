"""Starts the server detached from whatever window launched it.

    python -m apps.launcher

main() shows Hawkeye in a real window via apps/desktop.py wherever pywebview
is available, and only falls back to the browser-tab flow below that when
it is not (or fails outright). This module's own job stays the same either
way: find or start the server and hand back a URL, which is what
apps/desktop.py also calls into rather than duplicating.

The console the launcher runs in owns every process it starts: closing it
sends the whole tree a close event, which is why the old start.cmd had to
say "close this window to stop". Here the server is spawned as a separate,
console-less process instead, so the launcher can hand the browser a URL and
exit -- and the window it came from is free to close without taking the
scan running behind the page with it.

With no console, the server also has no stop button of its own. Two things
replace it: an already-running instance is reused rather than duplicated, so
launching twice cannot leave a hidden second copy, and the page carries a
"stop server" button that shuts down the one it is talking to.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LOG_PATH = ROOT / "data" / "server.log"
# The launcher's own outcome, separate from the server's output. It exits in
# about a second and its window goes with it, so "I double-clicked it and
# nothing happened" has to be answerable afterwards from somewhere.
LAUNCHER_LOG_PATH = ROOT / "data" / "launcher.log"
PORT_RANGE = range(8000, 8021)
STARTUP_TIMEOUT_SECONDS = 60
# What GET /health answers with. Any listener can occupy a port; only ours
# answers this, and reusing something else's port would be worse than
# starting on the next one.
HEALTH_MARKER = "hawkeye"


def record(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        LAUNCHER_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LAUNCHER_LOG_PATH, "a", encoding="utf-8") as log:
            log.write(f"{stamp} {message}\n")
    except OSError:
        # Being unable to write the diagnostic is not a reason to fail the
        # thing being diagnosed.
        pass


def health_of(port: int, timeout: float = 0.4) -> str | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as response:
            return json.loads(response.read()).get("app")
    except (OSError, ValueError):
        return None


def running_port() -> int | None:
    for port in PORT_RANGE:
        if health_of(port) == HEALTH_MARKER:
            return port
    return None


def free_port() -> int:
    """Asked of the OS by binding, not read out of a port table: a listener
    on one interface does not always show up in a scan, and a successful bind
    is the same question uvicorn is about to ask."""
    for port in PORT_RANGE:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    return PORT_RANGE.start


def server_executable() -> str:
    """pythonw.exe on Windows, so the spawned server has no console of its
    own to flash up. Falls back to python.exe where it is missing."""
    if sys.platform != "win32":
        return sys.executable
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate) if candidate.exists() else sys.executable


def spawn(port: int):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # A real file rather than DEVNULL: under pythonw a process with no valid
    # std handles gets sys.stdout/sys.stderr as None, and uvicorn hands its
    # stderr straight to a logging StreamHandler -- the first log line would
    # take the server down with an AttributeError. Handing it a file also
    # means a server that dies at startup leaves the reason on disk, which
    # is the only place left to look once there is no window.
    log = open(LOG_PATH, "a", encoding="utf-8", buffering=1)
    command = [server_executable(), "-m", "uvicorn", "apps.api.main:app",
               "--host", "127.0.0.1", "--port", str(port)]

    kwargs = {}
    if sys.platform == "win32":
        # DETACHED_PROCESS is the point of this module: without it the child
        # inherits this console and dies with it. NEW_PROCESS_GROUP keeps a
        # Ctrl-C in the launching window from reaching it too.
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        # The POSIX equivalent: a new session, so no terminal owns it and
        # closing the one it was started from sends it no hangup.
        kwargs["start_new_session"] = True

    return subprocess.Popen(command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                            stdout=log, stderr=log, close_fds=True, **kwargs)


def wait_until_serving(port: int, process) -> bool:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if health_of(port, timeout=1) == HEALTH_MARKER:
            return True
        time.sleep(0.2)
    return False


def main() -> int:
    os.chdir(ROOT)

    # A real window instead of a browser tab where one is available -- see
    # apps/desktop.py's own docstring for why. Anything short of a clean
    # exit (pywebview missing, or failing outright: a headless box, a Linux
    # desktop with no WebKit/Qt backend installed) falls back to the
    # browser flow below rather than leaving the user with nothing.
    try:
        from apps import desktop
    except ImportError:
        desktop = None
    if desktop is not None and desktop.available():
        try:
            return desktop.run()
        except Exception as e:
            record(f"desktop window failed ({type(e).__name__}: {e}); falling back to the browser")

    port = running_port()
    if port is not None:
        url = f"http://localhost:{port}"
        record(f"reused the server already running at {url}")
        print(f"Hawkeye is already running at {url}")
        print("Opening it in your browser.")
        open_browser(url)
        return 0

    port = free_port()
    record(f"starting a server on port {port} with {server_executable()}")
    process = spawn(port)
    if not wait_until_serving(port, process):
        record(f"the server did not come up on port {port}; see {LOG_PATH}")
        print(f"Hawkeye failed to start. See {LOG_PATH}", file=sys.stderr)
        return 1

    url = f"http://localhost:{port}"
    record(f"server up at {url}")
    print(f"Hawkeye is running at {url}")
    print("This window can be closed -- the server keeps running.")
    print("Closing the page in the browser stops it.")
    open_browser(url)
    return 0


def open_browser(url: str) -> None:
    """A browser that refuses to open is worth saying out loud: the window
    this prints into is about to close, and a URL nobody sees looks exactly
    like a launcher that did nothing."""
    try:
        opened = webbrowser.open(url)
    except Exception:
        opened = False
    if not opened:
        record(f"could not open a browser; the page is at {url}")
        print(f"Could not open a browser automatically -- open {url} yourself.")


if __name__ == "__main__":
    raise SystemExit(main())
