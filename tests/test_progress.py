"""Within-stage progress for a running scan."""
from apps.api.progress import ProgressRegistry


def test_unknown_scan_has_no_snapshot():
    assert ProgressRegistry().snapshot("nope") is None


def test_update_keeps_the_stage_and_its_start_time():
    registry = ProgressRegistry()
    registry.start_stage("s1", "verifying")
    first = registry.snapshot("s1")

    registry.update("s1", 3, 57)
    later = registry.snapshot("s1")

    assert (later.stage, later.done, later.total) == ("verifying", 3, 57)
    assert later.stage_elapsed >= first.stage_elapsed


def test_a_new_stage_resets_the_counts():
    registry = ProgressRegistry()
    registry.start_stage("s1", "verifying")
    registry.update("s1", 57, 57)

    registry.start_stage("s1", "reporting")
    snapshot = registry.snapshot("s1")

    assert (snapshot.stage, snapshot.done, snapshot.total) == ("reporting", 0, 0)


def test_update_without_a_stage_still_records_counts():
    registry = ProgressRegistry()
    registry.update("s1", 2, 10)

    snapshot = registry.snapshot("s1")

    assert (snapshot.done, snapshot.total) == (2, 10)
    assert snapshot.stage == ""


def test_clear_forgets_the_scan():
    registry = ProgressRegistry()
    registry.start_stage("s1", "verifying")

    registry.clear("s1")

    assert registry.snapshot("s1") is None
    registry.clear("s1")  # clearing twice is what the pipeline's finally does


def test_scans_do_not_share_progress():
    registry = ProgressRegistry()
    registry.start_stage("s1", "verifying")
    registry.start_stage("s2", "scanning")
    registry.update("s1", 4, 9)

    assert registry.snapshot("s1").done == 4
    assert registry.snapshot("s2").done == 0
