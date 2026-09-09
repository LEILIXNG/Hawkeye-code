"""Endpoints about the process itself rather than about scans.

The server runs with no console once start.cmd detaches it, so these are how
the launcher recognises an instance that is already up and how the page
shuts one down.
"""
import signal
import threading
import time

from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from fastapi import Depends

from apps.api import models
from apps.api.database import get_db
from apps.api.routers.scans import RUNNING_STATUSES
from apps.api.watchdog import IDLE_TIMEOUT_SECONDS, watchdog

router = APIRouter(tags=["server"])

SHUTDOWN_DELAY_SECONDS = 0.3


@router.get("/health")
def health():
    return {"app": "hawkeye"}


@router.post("/heartbeat")
def heartbeat(db: Session = Depends(get_db)):
    """The open page saying it is still there. The first one also arms the
    watchdog -- before it, a server whose browser never opened would time
    itself out while the user was still looking for the window.

    It answers with whether anything is running, because the page cannot
    work that out for itself: it only polls the scan whose row is open, so
    selecting another task would otherwise leave its "leaving will interrupt
    a scan" guard armed forever, or disarmed while a scan really is going.
    """
    watchdog.beat()
    running = db.query(models.Scan).filter(models.Scan.status.in_(RUNNING_STATUSES)).count()
    return {"ok": True, "interval": IDLE_TIMEOUT_SECONDS, "scan_running": running > 0}


@router.post("/page-closing")
def page_closing():
    """Sent by a page being closed, as a beacon, so a deliberate close does
    not wait out the whole idle timeout. Advisory only: a reload sends this
    too, and the reloaded page's next beat cancels it."""
    watchdog.page_closing()
    return {"ok": True}


def _raise_shutdown_signal() -> None:
    # SIGINT rather than killing the process: it is the signal uvicorn
    # already installs a handler for, so the shutdown runs the same way
    # Ctrl-C in a console would -- lifespan teardown included. Delayed so
    # this request's response is on the wire before the server stops
    # listening; a caller that gets a connection reset instead of an answer
    # cannot tell "stopped" from "crashed".
    time.sleep(SHUTDOWN_DELAY_SECONDS)
    signal.raise_signal(signal.SIGINT)


@router.post("/shutdown")
def shutdown(force: bool = False, db: Session = Depends(get_db)):
    """Stop the server. Refuses while a scan is running unless forced --
    the pipeline runs inside this process, so stopping now loses it."""
    running = db.query(models.Scan).filter(models.Scan.status.in_(RUNNING_STATUSES)).count()
    if running and not force:
        raise HTTPException(409, f"{running} scan(s) still running")

    threading.Thread(target=_raise_shutdown_signal, daemon=True).start()
    return {"stopping": True, "interrupted_scans": running}
