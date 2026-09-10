"""A real window for Hawkeye instead of a browser tab.

apps/launcher.py's main() tries this first and falls back to opening a
system browser tab when pywebview is not installed, or when it fails to
produce a window at all (a headless box, a Linux desktop with neither
GTK-WebKit nor Qt installed). It reuses launcher.py's port/spawn/health
logic rather than duplicating it -- this module is a different way to
*show* the server, not a different server.

Why this exists -- two problems with the browser-tab-plus-heartbeat setup
it replaces:

Starting was silent. The launcher's console printed nothing until
wait_until_serving() finished, up to 60s later, so a slow start (or a
Windows Defender scan of a freshly-written pythonw invocation) looked
exactly like a launcher that had done nothing. A window shown the instant
this process starts, before the server is even spawned, fixes that by
construction -- there is no "before the window exists" for the user to
stare at.

Stopping was probabilistic. apps/api/watchdog.py inferred "the page is
gone" from a 20-second gap in a 3-second JS heartbeat, and a backgrounded
browser tab's timers get throttled by the browser itself for reasons that
have nothing to do with whether the user is still looking at it -- a tab
switch or a few seconds of the OS suspending timers past that gap reads as
a closed page. A native window's own close event is authoritative and
immediate, so the window that owns the server now stops it directly, on
that event, instead of the server guessing from a timer gap. The 20s
heartbeat stays as the backstop for a window that vanishes without firing
the event at all (killed from Task Manager, a crash) -- it does not need to
be tight for that case, since nobody is watching the screen when it happens.
"""
from __future__ import annotations

import sys
import threading
import time
import urllib.error
import urllib.request
from html import escape

from apps import launcher

# Set at import, not inside run(): the delay before this module even loads
# (Python startup, or an antivirus scan of a freshly-installed package) is
# part of what "how long did startup take" has to answer too, and this is
# the earliest point that can be measured from.
_PROCESS_START = time.monotonic()

WINDOW_TITLE = "Hawkeye"
WINDOW_SIZE = (1280, 860)
WINDOW_MIN_SIZE = (900, 600)

# How much of data/server.log to show on a failed start -- enough to show
# the actual traceback without the window turning into a log viewer.
LOG_TAIL_LINES = 40

_PAGE_STYLE = """
  :root { color-scheme: light dark; --bg: #f6f7f9; --text: #1a1d23; --muted: #6b7280;
          --border: #e3e5e9; --danger: #d64545; --mono: ui-monospace, Consolas, monospace; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14161a; --text: #e6e8eb; --muted: #9aa2ad; --border: #2a2d33; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: var(--bg); color: var(--text); font: 14px/1.6 -apple-system, "Segoe UI", sans-serif; }
  .box { text-align: center; padding: 2rem; max-width: 32rem; }
  .spinner { width: 2rem; height: 2rem; margin: 0 auto 1.25rem; border-radius: 50%;
             border: 3px solid var(--border); border-top-color: var(--muted);
             animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 1.05rem; font-weight: 600; margin: 0 0 0.4rem; }
  p { color: var(--muted); margin: 0; }
  .elapsed { font-variant-numeric: tabular-nums; }
  .error h1 { color: var(--danger); }
  pre { text-align: left; background: var(--border); border-radius: 8px; padding: 0.75rem;
        margin-top: 1rem; font: 12px/1.5 var(--mono); overflow: auto; max-height: 40vh; }
"""


def _progress_html(message: str) -> str:
    """The very first thing the window shows -- rendered from a plain
    string with no network round trip, so it is on screen before the server
    has even been asked to start. The elapsed counter ticks locally in the
    page's own JS; the Python side only ever replaces this page once, on
    success or failure, rather than repainting it every second itself."""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{WINDOW_TITLE}</title><style>{_PAGE_STYLE}</style></head>
<body><div class="box">
  <div class="spinner"></div>
  <h1>{escape(message)}</h1>
  <p>已等待 <span id="s" class="elapsed">0</span> 秒</p>
</div>
<script>
  let n = 0;
  setInterval(() => {{ n += 1; document.getElementById('s').textContent = n; }}, 1000);
</script>
</body></html>"""


def _error_html(reason: str, log_path) -> str:
    tail = _tail(log_path, LOG_TAIL_LINES)
    log_block = f"<pre>{escape(tail)}</pre>" if tail else ""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{WINDOW_TITLE}</title><style>{_PAGE_STYLE}</style></head>
<body><div class="box error">
  <h1>Hawkeye 启动失败</h1>
  <p>{escape(reason)}</p>
  <p>完整日志见 <code>{escape(str(log_path))}</code></p>
  {log_block}
</div></body></html>"""


def _tail(path, lines: int) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def available() -> bool:
    """Whether pywebview is installed at all. Import errors from *inside*
    it (a backend it needs missing, no display) are not this module's to
    predict -- run() catches those and main() falls back the same way."""
    try:
        import webview  # noqa: F401
    except ImportError:
        return False
    return True


class _Owner:
    """Whether this process is the one that started the server, and so is
    the one responsible for stopping it. A second launch that finds one
    already running is a guest: closing its window shows nothing more than
    that window closing."""

    def __init__(self) -> None:
        self.is_owner = False
        self.base_url = ""
        self.process = None


def _post(url: str, timeout: float = 5.0) -> None:
    urllib.request.urlopen(urllib.request.Request(url, method="POST", data=b""), timeout=timeout)


def _bring_up_server(owner: _Owner, window) -> None:
    """Runs on a background thread started right after the window appears,
    so the window itself -- not this function's first line -- is the first
    thing the user sees. Ends by replacing the loading page with either the
    real app (load_url) or a diagnosis (load_html), never by leaving it
    spinning forever."""
    probe_start = time.monotonic()
    port = launcher.running_port()
    launcher.record(f"desktop: checked for a running server in {time.monotonic() - probe_start:.1f}s")
    if port is not None:
        owner.base_url = f"http://localhost:{port}"
        launcher.record(f"desktop: reusing the server already running at {owner.base_url} "
                        f"({_since_start():.1f}s since this process started)")
        window.load_url(owner.base_url)
        return

    port = launcher.free_port()
    launcher.record(f"desktop: starting a server on port {port} with {launcher.server_executable()}")
    process = launcher.spawn(port)
    # Taken on immediately, before health is known: a window closed while
    # still on the loading screen must still stop the process it started,
    # or it leaks a server nobody is looking at. See _stop_server().
    owner.is_owner = True
    owner.base_url = f"http://localhost:{port}"
    owner.process = process

    deadline = time.monotonic() + launcher.STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            launcher.record(f"desktop: the server process exited before it came up; see {launcher.LOG_PATH}")
            window.load_html(_error_html("服务器进程在启动完成前退出了。", launcher.LOG_PATH))
            return
        if launcher.health_of(port, timeout=1) == launcher.HEALTH_MARKER:
            launcher.record(f"desktop: server up at {owner.base_url} "
                            f"({_since_start():.1f}s since this process started)")
            window.load_url(owner.base_url)
            return
        time.sleep(0.2)

    launcher.record(f"desktop: the server did not come up on port {port}; see {launcher.LOG_PATH}")
    window.load_html(_error_html(f"服务器在 {launcher.STARTUP_TIMEOUT_SECONDS} 秒内没有响应。", launcher.LOG_PATH))


def _since_start() -> float:
    return time.monotonic() - _PROCESS_START


def _stop_server(owner: _Owner) -> bool:
    """Tries a clean stop; True means the server is stopping or already
    gone and the window may close. False means it refused because a scan
    is running -- the caller's job, not this function's, to ask the user
    whether to force it anyway."""
    try:
        _post(f"{owner.base_url}/shutdown")
        return True
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return False
        launcher.record(f"desktop: /shutdown answered {e.code}; closing the window anyway")
        return True
    except (OSError, urllib.error.URLError):
        # Not reachable: crashed already, or the loading screen's window was
        # closed before the server ever finished starting. Either way there
        # is no HTTP endpoint left to ask nicely, so take down the process
        # this window itself started, if it is still there.
        _terminate_owned_process(owner)
        return True


def _force_stop(owner: _Owner) -> None:
    try:
        _post(f"{owner.base_url}/shutdown?force=true")
    except (OSError, urllib.error.URLError):
        _terminate_owned_process(owner)


def _terminate_owned_process(owner: _Owner) -> None:
    if owner.process is not None and owner.process.poll() is None:
        owner.process.terminate()


def _make_on_closing(owner: _Owner, window):
    """The window's closing handler. pywebview runs this synchronously and
    cancels the close if it returns False -- the same veto a browser's
    beforeunload dialog gives the page today, but decided here instead of
    trusted to a native window chrome that may not run page JS at all on
    its own close button."""

    def on_closing():
        if not owner.is_owner:
            return None
        if _stop_server(owner):
            return None
        if window.create_confirmation_dialog("扫描仍在进行", "关闭窗口会中断正在运行的扫描。确定要关闭吗？"):
            _force_stop(owner)
            return None
        return False

    return on_closing


def _console_window():
    """The win32 handle of whatever console this process is attached to, or
    None off Windows or when there is none (already pythonw, or detached)."""
    if sys.platform != "win32":
        return None
    import ctypes

    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    return hwnd or None


def _set_console_visible(visible: bool) -> None:
    """start.cmd runs `python -m apps.launcher` *synchronously*, so this
    process shares its cmd.exe parent's console for as long as run() blocks
    -- the whole session, now that the window replaces the old
    print-and-exit browser flow. Unlike that flow, this one never writes
    anything to stdout, so left alone that console sits there blank for the
    entire session: not a launcher that silently did nothing, but close
    enough to look exactly like one. Hidden here rather than avoided by
    detaching a new process for it, which would need pythonw and so lose
    the console entirely for the fallback browser path, where a missing
    Python or a launcher crash still needs somewhere to print to."""
    hwnd = _console_window()
    if hwnd is None:
        return
    import ctypes

    ctypes.windll.user32.ShowWindow(hwnd, 5 if visible else 0)  # SW_SHOW / SW_HIDE


def run() -> int:
    """The desktop entry point. Blocks until the window (or the last of
    several, if more than one gets opened) closes."""
    import webview

    _set_console_visible(False)
    try:
        owner = _Owner()
        window = webview.create_window(
            WINDOW_TITLE, html=_progress_html("正在启动 Hawkeye..."),
            width=WINDOW_SIZE[0], height=WINDOW_SIZE[1], min_size=WINDOW_MIN_SIZE,
        )
        window.events.closing += _make_on_closing(owner, window)

        def bootstrap():
            launcher.record(f"desktop: window shown after {_since_start():.1f}s; bringing up the server")
            _bring_up_server(owner, window)

        window.events.shown += lambda: threading.Thread(target=bootstrap, daemon=True).start()

        webview.start()
        return 0
    finally:
        # Whether the window closed normally or webview blew up and this is
        # about to fall back to the browser flow -- either way, the next
        # thing to happen wants a console again: start.cmd's own error
        # check and pause, or the fallback flow's own print()s.
        _set_console_visible(True)


if __name__ == "__main__":
    raise SystemExit(run())
