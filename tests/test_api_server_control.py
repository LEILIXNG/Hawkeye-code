"""/health and /shutdown -- how the launcher recognises a live server and
how the page stops one that has no console of its own."""
from apps.api import models
from apps.api.routers import server as server_router
from tests.test_api import client  # noqa: F401  -- the shared app/db fixture


def test_health_answers_with_the_marker_the_launcher_looks_for(client):  # noqa: F811
    from apps.launcher import HEALTH_MARKER

    assert client.get("/health").json()["app"] == HEALTH_MARKER


def _scan_with_status(status: str) -> None:
    from apps.api.database import SessionLocal

    db = SessionLocal()
    project = models.Project(name="p", source_zip_filename="p.zip")
    db.add(project)
    db.commit()
    db.add(models.Scan(project_id=project.id, status=status))
    db.commit()
    db.close()


def test_shutdown_signals_the_server(client, monkeypatch):  # noqa: F811
    started = []
    monkeypatch.setattr(server_router.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: started.append(target)})())

    body = client.post("/shutdown").json()

    assert body == {"stopping": True, "interrupted_scans": 0}
    assert started and started[0] is server_router._raise_shutdown_signal


def test_shutdown_refuses_while_a_scan_is_running(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(server_router.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: None})())
    _scan_with_status("verifying")

    response = client.post("/shutdown")

    assert response.status_code == 409
    assert "running" in response.json()["detail"]


def test_force_stops_anyway_and_says_what_it_cost(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(server_router.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: None})())
    _scan_with_status("verifying")

    body = client.post("/shutdown", params={"force": "true"}).json()

    assert body == {"stopping": True, "interrupted_scans": 1}


def test_a_finished_scan_does_not_block_shutdown(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(server_router.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: None})())
    _scan_with_status("done")
    _scan_with_status("failed")

    assert client.post("/shutdown").status_code == 200


def test_heartbeat_arms_the_watchdog(client, monkeypatch):  # noqa: F811
    from apps.api.watchdog import watchdog

    assert watchdog.expired() is False  # nothing armed yet
    body = client.post("/heartbeat").json()

    assert body["ok"] is True
    assert body["interval"] > 0
    assert watchdog.expired() is False


def test_page_closing_is_accepted_as_a_beacon(client):  # noqa: F811
    assert client.post("/page-closing").json() == {"ok": True}
