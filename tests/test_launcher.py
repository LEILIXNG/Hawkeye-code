"""Launcher decisions: which port, whose server, how it is spawned."""
import subprocess
import sys
from pathlib import Path

import pytest

from apps import launcher


def test_running_port_finds_our_own_server(monkeypatch):
    monkeypatch.setattr(launcher, "PORT_RANGE", range(8000, 8004))
    monkeypatch.setattr(launcher, "health_of",
                        lambda port, timeout=0.4: "hawkeye" if port == 8002 else None)

    assert launcher.running_port() == 8002


def test_running_port_checks_every_port_in_parallel_not_one_at_a_time(monkeypatch):
    """Measured on a real machine: a closed port in this range did not fail
    fast here -- connecting to it took the full health_of() timeout instead
    of an instant refusal, which made the old one-port-at-a-time loop cost
    20 wasted timeouts (8.5s) before the server was even asked to start.
    Simulated the same way here -- a slow health_of() on every port -- so
    this pins the fix without depending on that machine-specific slowness
    actually reproducing under pytest."""
    import time

    monkeypatch.setattr(launcher, "PORT_RANGE", range(8000, 8010))
    slow_timeout = 0.3

    def slow_health_of(port, timeout=0.4):
        time.sleep(slow_timeout)
        return None

    monkeypatch.setattr(launcher, "health_of", slow_health_of)

    t0 = time.monotonic()
    assert launcher.running_port() is None
    elapsed = time.monotonic() - t0

    # One timeout's worth, generously bounded -- not ten of them.
    assert elapsed < slow_timeout * 3


def test_a_stranger_on_the_port_is_not_reused(monkeypatch):
    """Anything can be listening on 8000; only our server answers /health
    with the marker, and adopting someone else's port would be worse than
    moving to the next one."""
    monkeypatch.setattr(launcher, "PORT_RANGE", range(8000, 8004))
    monkeypatch.setattr(launcher, "health_of", lambda port, timeout=0.4: "something-else")

    assert launcher.running_port() is None


def test_health_of_swallows_a_dead_port():
    # Nothing is listening on a port picked and released a moment ago.
    port = launcher.free_port()
    assert launcher.health_of(port, timeout=0.2) is None


def test_free_port_returns_a_bindable_port():
    import socket

    port = launcher.free_port()

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))  # would raise if the answer were wrong


def test_free_port_falls_back_when_the_range_is_full(monkeypatch):
    monkeypatch.setattr(launcher, "PORT_RANGE", range(9100, 9102))

    import socket

    held = []
    try:
        for port in launcher.PORT_RANGE:
            s = socket.socket()
            s.bind(("127.0.0.1", port))
            s.listen(1)
            held.append(s)
        assert launcher.free_port() == 9100
    finally:
        for s in held:
            s.close()


@pytest.mark.skipif(sys.platform != "win32", reason="pythonw only exists on Windows")
def test_windows_spawns_the_console_less_interpreter():
    assert Path(launcher.server_executable()).name == "pythonw.exe"


def test_posix_spawns_the_running_interpreter(monkeypatch):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")

    assert launcher.server_executable() == sys.executable


def spawn_call(monkeypatch, tmp_path, platform):
    """spawn() with Popen replaced, on whichever platform's branch -- the
    detach flags are the contract worth pinning, and neither branch can be
    exercised on the machine the suite happens to run on."""
    captured = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(launcher.sys, "platform", platform)
    monkeypatch.setattr(launcher.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(launcher, "LOG_PATH", tmp_path / "data" / "server.log")
    launcher.spawn(8123)
    captured["kwargs"]["stdout"].close()
    return captured


def test_spawn_carries_the_port(monkeypatch, tmp_path):
    command = spawn_call(monkeypatch, tmp_path, sys.platform)["command"]

    assert command[1:] == ["-m", "uvicorn", "apps.api.main:app", "--host", "127.0.0.1", "--port", "8123"]


def test_windows_spawn_detaches_from_the_console(monkeypatch, tmp_path):
    """The whole point of the module: a child left in this console's process
    group dies with the window that started it."""
    flags = spawn_call(monkeypatch, tmp_path, "win32")["kwargs"]["creationflags"]

    assert flags & subprocess.DETACHED_PROCESS
    assert flags & subprocess.CREATE_NEW_PROCESS_GROUP


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_posix_spawn_leaves_the_terminals_session(monkeypatch, tmp_path, platform):
    kwargs = spawn_call(monkeypatch, tmp_path, platform)["kwargs"]

    assert kwargs["start_new_session"] is True
    assert "creationflags" not in kwargs


def test_spawn_gives_the_child_real_std_handles(monkeypatch, tmp_path):
    """Not DEVNULL: pythonw with no valid handles leaves sys.stderr as None,
    and uvicorn's first log line would then kill the server."""
    captured = {}
    monkeypatch.setattr(launcher.subprocess, "Popen",
                        lambda command, **kwargs: captured.update(kwargs) or object())
    log_path = tmp_path / "data" / "server.log"
    monkeypatch.setattr(launcher, "LOG_PATH", log_path)

    launcher.spawn(8123)

    assert captured["stdout"] is captured["stderr"]
    assert captured["stdout"].writable()
    captured["stdout"].close()
    assert log_path.exists()


def test_wait_until_serving_gives_up_on_a_child_that_died(monkeypatch):
    class Dead:
        def poll(self):
            return 1

    monkeypatch.setattr(launcher, "health_of", lambda port, timeout=0.4: None)

    assert launcher.wait_until_serving(8123, Dead()) is False


def test_record_appends_a_timestamped_line(monkeypatch, tmp_path):
    log = tmp_path / "data" / "launcher.log"
    monkeypatch.setattr(launcher, "LAUNCHER_LOG_PATH", log)

    launcher.record("first")
    launcher.record("second")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(" first") and lines[1].endswith(" second")


def test_record_never_fails_the_thing_it_is_recording(monkeypatch, tmp_path):
    """A read-only or missing data/ is not a reason to refuse to start."""
    monkeypatch.setattr(launcher, "LAUNCHER_LOG_PATH", tmp_path / "nope" / "launcher.log")
    monkeypatch.setattr(launcher.Path, "mkdir",
                        lambda self, **kwargs: (_ for _ in ()).throw(OSError("read-only")))

    launcher.record("still fine")


def test_a_browser_that_will_not_open_says_so(monkeypatch, tmp_path, capsys):
    """The window this prints into is about to close, and a URL nobody sees
    looks exactly like a launcher that did nothing."""
    monkeypatch.setattr(launcher, "LAUNCHER_LOG_PATH", tmp_path / "launcher.log")
    monkeypatch.setattr(launcher.webbrowser, "open", lambda url: False)

    launcher.open_browser("http://localhost:8000")

    assert "http://localhost:8000" in capsys.readouterr().out


def test_a_browser_that_raises_is_treated_as_not_opened(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(launcher, "LAUNCHER_LOG_PATH", tmp_path / "launcher.log")

    def boom(url):
        raise RuntimeError("no display")

    monkeypatch.setattr(launcher.webbrowser, "open", boom)

    launcher.open_browser("http://localhost:8000")

    assert "open http://localhost:8000 yourself" in capsys.readouterr().out


def test_start_cmd_keeps_crlf_endings():
    """cmd.exe parses a batch file with bare LF endings unreliably, and
    .gitattributes pins it -- a file written from a POSIX tool drifts."""
    data = (Path(launcher.ROOT) / "start.cmd").read_bytes()

    assert data.count(b"\n") == data.count(b"\r\n")
    assert data.count(b"\r\n") > 0


def test_start_sh_keeps_lf_endings():
    """The mirror case, and the worse one: a CRLF shebang makes the kernel
    report "bad interpreter" on mac and Linux."""
    data = (Path(launcher.ROOT) / "start.sh").read_bytes()

    assert data.count(b"\r\n") == 0
    assert data.startswith(b"#!/usr/bin/env bash\n")


def test_both_launchers_call_the_same_entry_point():
    """The platform differences are meant to live in launcher.py, not in two
    scripts that drift apart."""
    root = Path(launcher.ROOT)
    cmd = (root / "start.cmd").read_text(encoding="utf-8")
    sh = (root / "start.sh").read_text(encoding="utf-8")

    assert "-m apps.launcher" in cmd
    assert "-m apps.launcher" in sh


class TestMainTriesTheDesktopWindowFirst:
    """main() is what start.cmd/start.sh actually call -- the window is
    opt-in only in the sense that it degrades to the old browser flow, never
    in the sense of needing a flag or a second entry point.

    Patched on the real `apps.desktop` module's own attributes, not swapped
    in via sys.modules: main() does `from apps import desktop` fresh on every
    call, and once anything in the process has imported the real module
    (tests/test_desktop.py does, earlier in this same file's collection
    order), that lookup resolves through the `apps` package's own cached
    attribute rather than sys.modules -- a sys.modules substitute is silently
    ignored, and main() calls the *real* desktop.run(), which opens an
    actual pywebview window and leaves its bootstrap thread running past the
    end of the test. Patching the module's attributes in place works
    regardless of which lookup path resolves it.
    """

    def test_desktop_run_is_used_when_available(self, monkeypatch):
        from apps import desktop

        monkeypatch.setattr(desktop, "available", lambda: True)
        monkeypatch.setattr(desktop, "run", lambda: 0)
        monkeypatch.setattr(launcher, "running_port", lambda: (_ for _ in ()).throw(
            AssertionError("the browser flow must not run when the window succeeds")))

        assert launcher.main() == 0

    def test_a_missing_pywebview_falls_back_to_the_browser_flow(self, monkeypatch):
        from apps import desktop

        monkeypatch.setattr(desktop, "available", lambda: False)
        monkeypatch.setattr(launcher, "running_port", lambda: 8099)
        monkeypatch.setattr(launcher, "open_browser", lambda url: None)

        assert launcher.main() == 0

    def test_a_window_that_raises_falls_back_to_the_browser_flow(self, monkeypatch, tmp_path):
        from apps import desktop

        def boom():
            raise RuntimeError("no WebView2 runtime")

        monkeypatch.setattr(desktop, "available", lambda: True)
        monkeypatch.setattr(desktop, "run", boom)
        monkeypatch.setattr(launcher, "LAUNCHER_LOG_PATH", tmp_path / "launcher.log")
        monkeypatch.setattr(launcher, "running_port", lambda: 8099)
        monkeypatch.setattr(launcher, "open_browser", lambda url: None)

        assert launcher.main() == 0
