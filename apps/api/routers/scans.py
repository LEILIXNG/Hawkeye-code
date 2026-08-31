import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from apps.api import models, schemas
from apps.api.database import SessionLocal, get_db
from llm_gateway.config import provider_and_model_from_config
from scanner.common import REPORTS_DIR, UPLOADS_DIR, WORKSPACES_DIR
from scanner.pipeline import PipelineError, run_pipeline

router = APIRouter(tags=["scans"])

# Everything that isn't a terminal state. A scan sitting in one of these has
# a background task still writing to its workspace and report directory.
RUNNING_STATUSES = frozenset({"queued", "ingesting", "scanning", "verifying", "translating", "reporting"})


def _active_llm_config(db: Session) -> models.LLMConfig | None:
    return db.query(models.LLMConfig).filter_by(is_active=True).first()


def _resolve_llm_config(db: Session, llm_config_id: str | None) -> models.LLMConfig | None:
    """None means "use whatever's active" (the pre-existing default); a
    specific id means the user picked a saved config for this one scan,
    overriding whatever happens to be active."""
    if llm_config_id is None:
        return _active_llm_config(db)
    llm_config = db.get(models.LLMConfig, llm_config_id)
    if llm_config is None:
        raise HTTPException(404, "llm config not found")
    return llm_config


@router.post("/scans", response_model=schemas.ScanOut)
def create_scan(payload: schemas.ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    project = db.get(models.Project, payload.project_id)
    if project is None:
        raise HTTPException(404, "project not found")

    llm_config = _resolve_llm_config(db, payload.llm_config_id)
    try:
        provider_and_model_from_config(llm_config)
    except ValueError as e:
        raise HTTPException(400, str(e))

    scan = models.Scan(project_id=project.id, status="queued", llm_config_id=llm_config.id if llm_config else None)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id, project.id, project.source_zip_filename)
    return scan


def _run_scan(scan_id: str, project_id: str, source_zip_filename: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # scan.llm_config_id was pinned at creation time so the scan keeps
        # using the config the user picked even if the active/saved configs
        # change while this scan is queued or running.
        llm_config = db.get(models.LLMConfig, scan.llm_config_id) if scan.llm_config_id else _active_llm_config(db)
        provider, model = provider_and_model_from_config(llm_config)

        def on_status(status: str) -> None:
            scan.status = status
            db.commit()

        zip_path = UPLOADS_DIR / f"{project_id}.zip"
        workspace_dir = WORKSPACES_DIR / scan_id
        report_dir = REPORTS_DIR / scan_id

        result = run_pipeline(
            zip_path=zip_path,
            workspace_dir=workspace_dir,
            report_dir=report_dir,
            project_name=source_zip_filename,
            provider=provider,
            model=model,
            on_status=on_status,
        )

        _persist_candidates_and_findings(db, scan_id, report_dir, model)

        report = models.Report(
            scan_id=scan_id,
            html_path=result["html_path"],
            json_path=result["json_path"],
            summary=result["summary"],
        )
        db.add(report)
        scan.status = "done"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    except PipelineError as e:
        scan = db.get(models.Scan, scan_id)
        scan.status = "failed"
        scan.error_message = str(e)
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:  # unexpected bug in the pipeline itself
        scan = db.get(models.Scan, scan_id)
        scan.status = "failed"
        scan.error_message = f"internal error: {e}"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def _persist_candidates_and_findings(db: Session, scan_id: str, report_dir: Path, model: str) -> None:
    from scanner.common import load_json

    data = load_json(report_dir / "report.json")
    for item in data.get("findings", []):
        candidate = models.Candidate(
            scan_id=scan_id,
            rule_id=item.get("rule_id") or ",".join(item.get("rule_ids", [])),
            cwe=item.get("cwe"),
            owasp=item.get("owasp"),
            source_file=item["source_file"],
            source_line=item["source_line"],
            sink_file=item["sink_file"],
            sink_line=item["sink_line"],
            dedup_key=item["dedup_key"],
            is_intraprocedural=item.get("is_intraprocedural", True),
            severity=item.get("severity"),
        )
        db.add(candidate)
        db.flush()

        finding = item.get("finding") or {}
        db.add(models.Finding(
            candidate_id=candidate.id,
            reachable=finding.get("reachable", "uncertain"),
            sanitized=finding.get("sanitized"),
            confidence=finding.get("confidence"),
            reasoning=finding.get("reasoning"),
            exploit_scenario=finding.get("exploit_scenario"),
            severity=item.get("severity"),
            verifier_model=model,
        ))
    db.commit()


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@router.get("/scans/{scan_id}/report", response_model=schemas.ReportOut)
def get_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    if scan.status != "done" or scan.report is None:
        raise HTTPException(409, f"report not ready, scan status is '{scan.status}'")

    return schemas.ReportOut(
        scan_id=scan_id,
        summary=schemas.ReportSummary(**scan.report.summary),
        html_url=f"/scans/{scan_id}/report.html",
        json_url=f"/scans/{scan_id}/report.json",
    )


@router.get("/scans/{scan_id}/report.html")
def get_report_html(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None or scan.report is None:
        raise HTTPException(404, "report not found")
    return FileResponse(scan.report.html_path, media_type="text/html")


@router.get("/scans/{scan_id}/report.json")
def get_report_json(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None or scan.report is None:
        raise HTTPException(404, "report not found")
    return FileResponse(scan.report.json_path, media_type="application/json")


def _remove_scan_dir(parent: Path, scan_id: str) -> None:
    """Delete parent/scan_id, refusing anything that resolves outside parent.

    scan_id is always a database primary key by the time it gets here, never
    the raw path segment -- but this is the only place in the app where a
    value that arrived in a URL reaches rmtree, so it is checked instead of
    assumed.
    """
    target = (parent / scan_id).resolve()
    if target.parent != parent.resolve() or not target.is_dir():
        return
    shutil.rmtree(target, ignore_errors=True)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    if scan.status in RUNNING_STATUSES:
        raise HTTPException(409, f"scan is still running (status '{scan.status}')")

    project = scan.project
    _remove_scan_dir(WORKSPACES_DIR, scan.id)
    _remove_scan_dir(REPORTS_DIR, scan.id)
    db.delete(scan)  # cascades to candidates -> findings, and to the report row
    db.commit()

    # A project exists only to own the scans of one uploaded zip, and the
    # history list is built from scans -- so once the last scan is gone the
    # project row and its zip are unreachable from the UI and would sit in
    # data/uploads/ forever. Drop them with the scan that was keeping them
    # visible.
    if project is not None and not project.scans:
        (UPLOADS_DIR / f"{project.id}.zip").unlink(missing_ok=True)
        db.delete(project)
        db.commit()


@router.get("/projects", response_model=list[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).order_by(models.Project.created_at.desc()).all()


@router.get("/projects/{project_id}/scans", response_model=list[schemas.ScanOut])
def list_scans(project_id: str, db: Session = Depends(get_db)):
    return db.query(models.Scan).filter_by(project_id=project_id).order_by(models.Scan.started_at.desc()).all()
