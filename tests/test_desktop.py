"""apps/desktop.py -- the decisions around the pywebview window, not the
window itself. Nothing here creates a real window: webview.create_window()
and webview.start() need an actual GUI backend, which a test suite cannot
rely on having, so what is asserted is the ownership/stop logic and the
HTML it hands to a fake window -- the same fake-object style already used
for watchdog and cancellation in tests/test_watchdog.py and
tests/test_cancel.py.
"""
import urllib.error

import pytest

from apps import desktop


class FakeWindow:
    """Stands in for a pywebview Window: records what it was told to show,
    and answers a scripted yes/no for the confirmation dialog."""

    def __init__(self, confirm: bool = True):
        self.loaded_urls = []
        self.loaded_html = []
        self.confirm_answer = confirm
        self.confirm_calls = []

    def load_url(self, url):
        self.loaded_urls.append(url)

    def load_html(self, html):
        self.loaded_html.append(html)

    def create_confirmation_dialog(self, title, message):
        self.confirm_calls.append((title, message))
        return self.confirm_answer


class FakeProcess:
    def __init__(self, alive: bool = True):
        self.terminated = False
        self._alive = alive

    def poll(self):
        return None if self._alive else 1

    def terminate(self):
        self.terminated = True
        self._alive = False


class TestAvailable:
    def test_true_when_webview_imports(self, monkeypatch):
        import sys
        import types

        monkeypatch.setitem(sys.modules, "webview", types.ModuleType("webview"))

        assert desktop.available() is True

    def test_false_when_it_does_not(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "webview":
                raise ImportError("no module named webview")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)

        assert desktop.available() is False


class TestBringUpServer:
    """The decision that would otherwise happen twice: reuse a server
    that is already up, or start one and own it."""

    def test_an_existing_server_is_reused_and_not_owned(self, monkeypatch):
        monkeypatch.setattr(launcher := desktop.launcher, "running_port", lambda: 8007)
        spawned = []
        monkeypatch.setattr(launcher, "spawn", lambda port: spawned.append(port) or FakeProcess())

        owner = desktop._Owner()
        window = FakeWindow()
        desktop._bring_up_server(owner, window)

        assert owner.is_owner is False
        assert owner.base_url == "http://localhost:8007"
        assert window.loaded_urls == ["http://localhost:8007"]
        assert spawned == []  # never started a second one

    def test_a_fresh_server_is_owned_from_the_moment_it_is_spawned(self, monkeypatch):
        launcher = desktop.launcher
        monkeypatch.setattr(launcher, "running_port", lambda: None)
        monkeypatch.setattr(launcher, "free_port", lambda: 8010)
        process = FakeProcess()
        monkeypatch.setattr(launcher, "spawn", lambda port: process)
        monkeypatch.setattr(launcher, "health_of", lambda port, timeout=1: launcher.HEALTH_MARKER)
        monkeypatch.setattr(launcher, "server_executable", lambda: "python")

        owner = desktop._Owner()
        window = FakeWindow()
        desktop._bring_up_server(owner, window)

        assert owner.is_owner is True
        assert owner.process is process
        assert window.loaded_urls == ["http://localhost:8010"]

    def test_a_process_that_dies_before_coming_up_shows_the_error_page(self, monkeypatch, tmp_path):
        launcher = desktop.launcher
        monkeypatch.setattr(launcher, "running_port", lambda: None)
        monkeypatch.setattr(launcher, "free_port", lambda: 8011)
        monkeypatch.setattr(launcher, "spawn", lambda port: FakeProcess(alive=False))
        monkeypatch.setattr(launcher, "LOG_PATH", tmp_path / "server.log")

        owner = desktop._Owner()
        window = FakeWindow()
        desktop._bring_up_server(owner, window)

        assert window.loaded_urls == []
        assert len(window.loaded_html) == 1
        assert "启动失败" in window.loaded_html[0]

    def test_a_timeout_also_shows_the_error_page_not_a_blank_spinner(self, monkeypatch, tmp_path):
        """The whole point of the loading screen: it must resolve to
        something, one way or the other, never spin forever."""
        launcher = desktop.launcher
        monkeypatch.setattr(launcher, "running_port", lambda: None)
        monkeypatch.setattr(launcher, "free_port", lambda: 8012)
        monkeypatch.setattr(launcher, "spawn", lambda port: FakeProcess())
        monkeypatch.setattr(launcher, "health_of", lambda port, timeout=1: None)
        monkeypatch.setattr(launcher, "STARTUP_TIMEOUT_SECONDS", 0)
        monkeypatch.setattr(launcher, "LOG_PATH", tmp_path / "server.log")

        owner = desktop._Owner()
        window = FakeWindow()
        desktop._bring_up_server(owner, window)

        assert window.loaded_urls == []
        assert len(window.loaded_html) == 1


class TestErrorHtmlIncludesTheLog:
    def test_the_tail_of_the_log_is_embedded(self, tmp_path):
        log = tmp_path / "server.log"
        log.write_text("line one\nline two\nTraceback: boom\n", encoding="utf-8")

        html = desktop._error_html("it broke", log)

        assert "Traceback: boom" in html
        assert str(log) in html

    def test_a_missing_log_does_not_raise(self, tmp_path):
        html = desktop._error_html("it broke", tmp_path / "nope.log")

        assert "启动失败" in html


class TestStopServer:
    """Mirrors the page's own stop-server button: a plain call, a 409 read
    as "a scan is in the way", and anything unreachable treated as already
    gone -- the owned process is what is actually killed in that last case,
    not left running with nobody watching it."""

    def test_a_clean_shutdown_succeeds(self, monkeypatch):
        monkeypatch.setattr(desktop, "_post", lambda url, timeout=5.0: None)
        owner = desktop._Owner()
        owner.base_url = "http://localhost:8000"

        assert desktop._stop_server(owner) is True

    def test_a_409_reports_a_running_scan_instead_of_stopping(self, monkeypatch):
        def raise_409(url, timeout=5.0):
            raise urllib.error.HTTPError(url, 409, "scan running", None, None)

        monkeypatch.setattr(desktop, "_post", raise_409)
        owner = desktop._Owner()
        owner.base_url = "http://localhost:8000"

        assert desktop._stop_server(owner) is False

    def test_an_unreachable_server_terminates_the_owned_process_directly(self, monkeypatch):
        def raise_connection_error(url, timeout=5.0):
            raise OSError("connection refused")

        monkeypatch.setattr(desktop, "_post", raise_connection_error)
        owner = desktop._Owner()
        owner.base_url = "http://localhost:8000"
        owner.process = FakeProcess()

        assert desktop._stop_server(owner) is True
        assert owner.process.terminated is True

    def test_an_already_dead_process_is_left_alone(self, monkeypatch):
        def raise_connection_error(url, timeout=5.0):
            raise OSError("connection refused")

        monkeypatch.setattr(desktop, "_post", raise_connection_error)
        owner = desktop._Owner()
        owner.base_url = "http://localhost:8000"
        owner.process = FakeProcess(alive=False)

        desktop._stop_server(owner)

        assert owner.process.terminated is False  # terminate() not called again


class TestOnClosing:
    """The veto logic: only an owner is asked at all, and only a running
    scan gets a dialog -- everything else closes without bothering the
    user, the same way the page's own stop button does not ask twice."""

    def test_a_guest_window_closes_without_touching_the_server(self, monkeypatch):
        posts = []
        monkeypatch.setattr(desktop, "_post", lambda url, timeout=5.0: posts.append(url))
        owner = desktop._Owner()
        owner.is_owner = False
        window = FakeWindow()

        result = desktop._make_on_closing(owner, window)()

        assert result is None
        assert posts == []

    def test_an_owner_with_no_scan_running_closes_cleanly(self, monkeypatch):
        monkeypatch.setattr(desktop, "_post", lambda url, timeout=5.0: None)
        owner = desktop._Owner()
        owner.is_owner = True
        owner.base_url = "http://localhost:8000"
        window = FakeWindow()

        assert desktop._make_on_closing(owner, window)() is None
        assert window.confirm_calls == []

    def test_a_running_scan_is_confirmed_before_forcing_the_stop(self, monkeypatch):
        calls = []

        def fake_post(url, timeout=5.0):
            calls.append(url)
            if "force" not in url:
                raise urllib.error.HTTPError(url, 409, "scan running", None, None)

        monkeypatch.setattr(desktop, "_post", fake_post)
        owner = desktop._Owner()
        owner.is_owner = True
        owner.base_url = "http://localhost:8000"
        window = FakeWindow(confirm=True)

        assert desktop._make_on_closing(owner, window)() is None

        assert len(window.confirm_calls) == 1
        assert any("force=true" in c for c in calls)

    def test_declining_the_confirmation_vetoes_the_close(self, monkeypatch):
        def fake_post(url, timeout=5.0):
            raise urllib.error.HTTPError(url, 409, "scan running", None, None)

        monkeypatch.setattr(desktop, "_post", fake_post)
        owner = desktop._Owner()
        owner.is_owner = True
        owner.base_url = "http://localhost:8000"
        window = FakeWindow(confirm=False)

        assert desktop._make_on_closing(owner, window)() is False


class TestProgressHtml:
    def test_the_message_is_escaped(self):
        html = desktop._progress_html("<script>alert(1)</script>")

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
