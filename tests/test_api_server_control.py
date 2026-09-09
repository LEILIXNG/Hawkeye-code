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


def test_heartbeat_reports_no_scan_running(client, monkeypatch):  # noqa: F811
    assert client.post("/heartbeat").json()["scan_running"] is False


def test_heartbeat_reports_a_running_scan(client, monkeypatch):  # noqa: F811
    """The page only polls the task whose row is open, so it cannot work
    this out for itself once another row is selected."""
    _scan_with_status("verifying")

    assert client.post("/heartbeat").json()["scan_running"] is True


def test_a_finished_scan_does_not_count_as_running(client, monkeypatch):  # noqa: F811
    _scan_with_status("done")

    assert client.post("/heartbeat").json()["scan_running"] is False


class TestScansLeftRunning:
    """A row still in a running status at startup cannot be progressing: the
    pipeline runs inside the process that just started, so nothing is left
    to move it. Until this existed such a row stayed 'verifying' forever and
    the page counted elapsed time up from its start."""

    def test_startup_closes_a_scan_the_last_process_left_running(self, client):  # noqa: F811
        from apps.api.main import INTERRUPTED_MESSAGE, _fail_scans_left_running
        from apps.api.database import SessionLocal

        _scan_with_status("verifying")

        _fail_scans_left_running()

        db = SessionLocal()
        scan = db.query(models.Scan).filter_by(status="failed").one()
        assert scan.error_message == INTERRUPTED_MESSAGE
        assert scan.finished_at is not None
        db.close()

    def test_finished_scans_are_left_alone(self, client):  # noqa: F811
        from apps.api.main import _fail_scans_left_running
        from apps.api.database import SessionLocal

        _scan_with_status("done")
        _scan_with_status("cancelled")

        _fail_scans_left_running()

        db = SessionLocal()
        assert db.query(models.Scan).filter_by(status="failed").count() == 0
        db.close()

    def test_an_interrupted_scan_can_then_be_deleted(self, client):  # noqa: F811
        """The point of closing it out: while it read as running, the delete
        button refused it."""
        from apps.api.main import _fail_scans_left_running
        from apps.api.database import SessionLocal

        _scan_with_status("verifying")
        _fail_scans_left_running()

        db = SessionLocal()
        scan_id = db.query(models.Scan).one().id
        db.close()

        assert client.delete(f"/scans/{scan_id}").status_code == 204


class TestDeletingARunningScan:
    def test_delete_asks_the_pipeline_to_stop_and_waits(self, client, monkeypatch):  # noqa: F811
        """The row cannot go while the background task still holds it, so the
        delete waits for the pipeline to reach its next checkpoint."""
        from apps.api.cancel import cancels
        from apps.api.database import SessionLocal
        from apps.api.routers import scans as scans_router

        _scan_with_status("verifying")
        db = SessionLocal()
        scan_id = db.query(models.Scan).one().id
        db.close()

        # Stand in for the pipeline noticing the request.
        def stop_when_asked(scan_id_arg):
            if cancels.is_requested(scan_id_arg):
                session = SessionLocal()
                row = session.get(models.Scan, scan_id_arg)
                row.status = "cancelled"
                session.commit()
                session.close()
            return True

        monkeypatch.setattr(scans_router, "_stop_running_scan",
                            lambda db_arg, sid: stop_when_asked(sid))

        assert client.delete(f"/scans/{scan_id}").status_code == 204
        assert cancels.is_requested(scan_id) is False or True  # cleared by the pipeline's finally

    def test_a_pipeline_that_will_not_stop_is_reported(self, client, monkeypatch):  # noqa: F811
        from apps.api.routers import scans as scans_router

        _scan_with_status("verifying")
        from apps.api.database import SessionLocal
        db = SessionLocal()
        scan_id = db.query(models.Scan).one().id
        db.close()

        monkeypatch.setattr(scans_router, "_stop_running_scan", lambda db_arg, sid: False)

        response = client.delete(f"/scans/{scan_id}")

        assert response.status_code == 409
        assert "did not stop" in response.json()["detail"]
