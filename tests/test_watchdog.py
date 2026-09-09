"""The watchdog that ends the process when the page that was using it goes."""
import time

from apps.api.watchdog import PageWatchdog


def make(on_expire=lambda: None, is_busy=lambda: False, idle=0.2, grace=0.1, interval=0.02):
    return PageWatchdog(on_expire=on_expire, is_busy=is_busy,
                        idle_timeout=idle, close_grace=grace, check_interval=interval)


def test_nothing_expires_before_the_first_beat():
    """A server whose browser never opened must not time itself out while
    the user is still looking for the window."""
    dog = make()

    time.sleep(0.3)

    assert dog.expired() is False


def test_a_beat_arms_it_and_the_silence_that_follows_expires():
    dog = make()
    dog.beat()

    assert dog.expired() is False
    time.sleep(0.25)
    assert dog.expired() is True


def test_beats_keep_pushing_the_deadline_out():
    dog = make()
    for _ in range(4):
        dog.beat()
        time.sleep(0.08)

    assert dog.expired() is False


def test_a_close_beacon_pulls_the_deadline_in():
    dog = make(idle=10.0, grace=0.05)
    dog.beat()

    dog.page_closing()

    assert dog.expired() is False
    time.sleep(0.1)
    assert dog.expired() is True


def test_a_reload_cancels_its_own_close_beacon():
    """pagehide fires, then the fresh page beats a moment later -- that beat
    has to undo the beacon or every refresh would kill the server."""
    dog = make(idle=10.0, grace=0.05)
    dog.beat()
    dog.page_closing()

    dog.beat()

    time.sleep(0.1)
    assert dog.expired() is False


def test_a_beacon_before_any_beat_is_ignored():
    dog = make()

    dog.page_closing()

    time.sleep(0.15)
    assert dog.expired() is False


def test_a_beacon_never_extends_the_deadline():
    """One tab closing must not buy time for a server whose other tabs have
    already gone quiet."""
    dog = make(idle=0.05, grace=10.0)
    dog.beat()
    time.sleep(0.1)

    dog.page_closing()

    assert dog.expired() is True


def test_the_loop_fires_on_expiry():
    fired = []
    dog = make(on_expire=lambda: fired.append(True))
    dog.beat()
    dog.start()
    try:
        time.sleep(0.4)
    finally:
        dog.stop()

    assert fired == [True]


def test_a_running_scan_holds_the_process_open():
    """Losing ten minutes of LLM calls to a closed tab is worse than a
    server that outlives its page for a while."""
    fired = []
    busy = [True]
    dog = make(on_expire=lambda: fired.append(True), is_busy=lambda: busy[0])
    dog.beat()
    dog.start()
    try:
        time.sleep(0.4)
        assert fired == []

        busy[0] = False
        time.sleep(0.4)
    finally:
        dog.stop()

    assert fired == [True]


def test_stop_ends_the_thread():
    dog = make(idle=10.0)
    dog.start()
    dog.stop()

    dog.beat()
    time.sleep(0.1)
    dog.stop()  # stopping twice is what a failed startup would do
