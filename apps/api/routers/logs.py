from fastapi import APIRouter

from apps.api.runlog import run_log

router = APIRouter(tags=["logs"])


@router.get("/logs")
def get_logs(after: int = 0, scan_id: str | None = None):
    """Lines the server has printed since sequence number `after`, or only
    one scan's own lines when scan_id is given.

    Polled rather than streamed: the page already polls for scan status on a
    timer, and a second timer is a great deal less machinery than an SSE
    connection that has to be reopened every time the tab is backgrounded.
    """
    entries, latest = run_log.since(after, scan_id)
    return {"entries": entries, "next": latest}
