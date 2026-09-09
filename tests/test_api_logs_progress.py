"""The two endpoints the page's log panel and progress bar read.

Lines are fed to the buffer directly rather than printed: pytest swaps
sys.stderr for its own capture object, so a print here would never reach the
tee that runlog.install() put on the original stream. That the tee mirrors a
write at all is tests/test_runlog.py's job.
"""
import pytest

from apps.api import models
from apps.api.progress import registry
from apps.api.runlog import run_log
from tests.test_api import client  # noqa: F401  -- the shared app/db fixture


@pytest.fixture(autouse=True)
def clean_buffers():
    run_log.clear()
    yield
    run_log.clear()


def test_logs_endpoint_serves_what_the_server_printed(client):  # noqa: F811
    run_log.feed("[pipeline] verifying 3/57\n")

    body = client.get("/logs").json()

    assert [e["text"] for e in body["entries"]][-1] == "[pipeline] verifying 3/57"
    assert body["next"] >= 1


def test_logs_endpoint_is_incremental(client):  # noqa: F811
    run_log.feed("first\n")
    first = client.get("/logs").json()

    run_log.feed("second\n")
    second = client.get("/logs", params={"after": first["next"]}).json()

    assert [e["text"] for e in second["entries"]] == ["second"]
    assert client.get("/logs", params={"after": second["next"]}).json()["entries"] == []


def _scan_row(client, status="verifying"):  # noqa: F811
    from apps.api.database import SessionLocal

    db = SessionLocal()
    project = models.Project(name="p", source_zip_filename="p.zip")
    db.add(project)
    db.commit()
    scan = models.Scan(project_id=project.id, status=status)
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.close()
    return scan_id


def test_scan_without_a_running_stage_reports_no_progress(client):  # noqa: F811
    scan_id = _scan_row(client, status="done")

    body = client.get(f"/scans/{scan_id}").json()

    assert body["stage_done"] is None
    assert body["stage_total"] is None
    assert body["stage_elapsed"] is None


def test_scan_carries_the_live_stage_counts(client):  # noqa: F811
    scan_id = _scan_row(client)
    registry.start_stage(scan_id, "verifying")
    registry.update(scan_id, 3, 57)
    try:
        body = client.get(f"/scans/{scan_id}").json()
    finally:
        registry.clear(scan_id)

    assert body["stage_done"] == 3
    assert body["stage_total"] == 57
    assert body["stage_elapsed"] >= 0
    assert body["status"] == "verifying"


def test_a_stage_with_nothing_to_count_reports_no_progress(client):  # noqa: F811
    """total 0 is the ingest/scan stages, which never call on_progress -- a
    0/0 would draw an empty counter on the page rather than none at all."""
    scan_id = _scan_row(client, status="scanning")
    registry.start_stage(scan_id, "scanning")
    try:
        body = client.get(f"/scans/{scan_id}").json()
    finally:
        registry.clear(scan_id)

    assert body["stage_total"] is None


def test_logs_can_be_filtered_to_one_scan(client):  # noqa: F811
    from apps.api.runlog import active_scan

    run_log.feed("untagged" + chr(10))
    active_scan.set("scan-A")
    run_log.feed("[pipeline] verifying 1/3" + chr(10))
    active_scan.set("scan-B")
    run_log.feed("[pipeline] someone else" + chr(10))
    active_scan.set(None)

    body = client.get("/logs", params={"scan_id": "scan-A"}).json()

    assert [e["text"] for e in body["entries"]] == ["[pipeline] verifying 1/3"]


def test_the_filtered_high_water_mark_is_the_buffers(client):  # noqa: F811
    """Otherwise a caller polling one scan re-walks every line written for
    other reasons between its own."""
    from apps.api.runlog import active_scan

    active_scan.set("scan-A")
    run_log.feed("mine" + chr(10))
    active_scan.set(None)
    run_log.feed("someone else" + chr(10))

    body = client.get("/logs", params={"scan_id": "scan-A"}).json()

    assert len(body["entries"]) == 1
    # Absolute numbers are not asserted: clear() deliberately does not reset
    # the sequence, since restarting it would make every client re-read the
    # lines it already has.
    assert body["next"] > body["entries"][0]["seq"]
    assert client.get("/logs", params={"scan_id": "scan-A", "after": body["next"]}).json()["entries"] == []


def test_uvicorn_records_are_never_tagged_with_a_scan(client):  # noqa: F811
    """Access lines come from request threads; stamping the running scan on
    them would attribute someone else's traffic to it."""
    import logging

    from apps.api.runlog import _BufferHandler, active_scan

    handler = _BufferHandler(run_log)
    handler.setFormatter(logging.Formatter("%(message)s"))
    active_scan.set("scan-A")
    handler.emit(logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1, "startup", None, None))
    active_scan.set(None)

    assert client.get("/logs", params={"scan_id": "scan-A"}).json()["entries"] == []
    assert any(e["text"] == "startup" for e in client.get("/logs").json()["entries"])
