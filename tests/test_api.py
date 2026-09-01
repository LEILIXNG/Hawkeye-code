"""HTTP-contract tests for apps/api. These deliberately never trigger the
real pipeline (no semgrep subprocess, no LLM call) -- same rule Phase 0
follows for scripts/02_verify.py: nothing that costs money or needs the
network runs in the automated suite. scanner/pipeline.py itself was
exercised manually against a real target (see MEMORY.md).
"""
import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "")  # don't auto-seed from a real .env during tests
    monkeypatch.chdir(tmp_path)

    from apps.api import database as db_module
    from apps.api.database import Base

    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.sqlite3'}", connect_args={"check_same_thread": False})
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    monkeypatch.setattr(db_module, "engine", test_engine)
    monkeypatch.setattr(db_module, "SessionLocal", TestSessionLocal)

    monkeypatch.setattr("scanner.common.DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("scanner.common.UPLOADS_DIR", tmp_path / "uploads")

    from apps.api.main import app
    from apps.api.database import get_db
    from apps.api.routers import uploads as uploads_router

    monkeypatch.setattr(uploads_router, "UPLOADS_DIR", tmp_path / "uploads")

    # scans.py did `from scanner.common import ...`, binding these at import
    # time, so patching scanner.common above does not reach them. Without
    # this a test that renders a report writes it into the developer's real
    # data/reports/ -- which is exactly what happened, one leaked directory
    # per suite run, until 88 of them had piled up.
    from apps.api.routers import scans as scans_router

    monkeypatch.setattr(scans_router, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(scans_router, "WORKSPACES_DIR", tmp_path / "workspaces")
    monkeypatch.setattr(scans_router, "REPORTS_DIR", tmp_path / "reports")

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


def make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/A.java", "class A {}")
    return buf.getvalue()


class TestUploads:
    def test_rejects_non_zip_file(self, client):
        resp = client.post("/uploads", files={"file": ("notes.txt", b"hello", "text/plain")})
        assert resp.status_code == 400

    def test_accepts_zip_and_creates_project(self, client):
        resp = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        assert resp.status_code == 200
        body = resp.json()
        assert body["source_zip_filename"] == "demo.zip"
        assert body["name"] == "demo"


class TestProjectsAndScans:
    def test_list_projects_empty_initially(self, client):
        assert client.get("/projects").json() == []

    def test_get_nonexistent_scan_is_404(self, client):
        assert client.get("/scans/does-not-exist").status_code == 404

    def test_create_scan_for_missing_project_is_404(self, client):
        resp = client.post("/scans", json={"project_id": "nope"})
        assert resp.status_code == 404

    def test_create_scan_without_llm_config_is_400(self, client):
        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]
        resp = client.post("/scans", json={"project_id": project_id})
        assert resp.status_code == 400

    def test_create_scan_uses_the_explicitly_selected_llm_config(self, client, monkeypatch):
        # POST /scans's BackgroundTasks run synchronously under TestClient,
        # so stub out the pipeline itself (not just the LLM call) -- letting
        # the real one run would shell out to semgrep for no reason this
        # test cares about, on top of the no-real-LLM-calls rule.
        from apps.api import database as db_module
        from apps.api.routers import scans as scans_router
        from scanner.render import render as real_render

        translate_flags = []
        concurrencies = []

        def fake_run_pipeline(zip_path, workspace_dir, report_dir, project_name, provider, model,
                              on_status=lambda s: None, translate=True, concurrency=1):
            translate_flags.append(translate)
            concurrencies.append(concurrency)
            on_status("done")
            return real_render([], project_name, report_dir)

        monkeypatch.setattr(scans_router, "run_pipeline", fake_run_pipeline)
        # scans.py did `from apps.api.database import SessionLocal`, so it
        # captured whatever SessionLocal was at first import -- the
        # `client` fixture's monkeypatch of db_module.SessionLocal doesn't
        # reach that already-bound name. Patch scans.py's own copy too, or
        # the background task's db = SessionLocal() call opens a session
        # against a stale engine and can't find this test's scan row.
        monkeypatch.setattr(scans_router, "SessionLocal", db_module.SessionLocal)

        glm = client.post("/settings/llm", json={"name": "glm", "api_key": "sk-glm", "verify_model": "glm-4-flash"}).json()
        # Creating this second config auto-activates it, so glm above is
        # now the *inactive* one -- exactly the case worth covering, since
        # "pick a non-active saved config for just this scan" is the point
        # of this feature.
        client.post("/settings/llm", json={"name": "deepseek", "api_key": "sk-ds", "verify_model": "deepseek-chat"})

        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]

        resp = client.post("/scans", json={"project_id": project_id, "llm_config_id": glm["id"]})
        assert resp.status_code == 200
        scan_id = resp.json()["id"]
        assert resp.json()["llm_config_id"] == glm["id"]

        # Still pinned to glm after the (stubbed) pipeline finishes, not the
        # config that's active *now*.
        final = client.get(f"/scans/{scan_id}").json()
        assert final["llm_config_id"] == glm["id"]
        assert final["status"] == "done"
        # The web pipeline does not run the translate stage: it is a second
        # LLM pass per finding, and on a rate-limited endpoint it doubles
        # the chances of the 429 that fails the whole scan.
        assert translate_flags == [False]
        # Comes from the chosen config, which was saved without an explicit
        # value and so defaults to sequential.
        assert concurrencies == [1]

    def test_create_scan_with_unknown_llm_config_id_is_404(self, client):
        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]
        resp = client.post("/scans", json={"project_id": project_id, "llm_config_id": "does-not-exist"})
        assert resp.status_code == 404

    def test_report_not_ready_before_scan_completes(self, client):
        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]
        # Bypass the LLM-config gate to create a scan row directly for this check.
        from apps.api import models
        from apps.api.database import SessionLocal

        db = SessionLocal()
        scan = models.Scan(project_id=project_id, status="queued")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        resp = client.get(f"/scans/{scan_id}/report")
        assert resp.status_code == 409


class TestDeleteScan:
    """DELETE /scans/{id}. Scans are built straight in the database rather
    than by running a scan: this endpoint's job is row + directory removal,
    and going through the pipeline would only add a semgrep subprocess the
    assertions never look at.
    """

    def _setup(self, client, tmp_path, status="done"):
        # The client fixture already points scans.py's UPLOADS_DIR /
        # WORKSPACES_DIR / REPORTS_DIR at tmp_path, so the directories built
        # below are the ones the endpoint will delete.
        from apps.api import database as db_module, models

        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]

        db = db_module.SessionLocal()
        scan = models.Scan(project_id=project_id, status=status)
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        dirs = []
        for parent in ("workspaces", "reports"):
            d = tmp_path / parent / scan_id
            d.mkdir(parents=True)
            (d / "marker.txt").write_text("x")
            dirs.append(d)
        return project_id, scan_id, dirs

    def test_delete_missing_scan_is_404(self, client):
        assert client.delete("/scans/nope").status_code == 404

    def test_delete_removes_the_scan_and_its_directories(self, client, tmp_path):
        _, scan_id, dirs = self._setup(client, tmp_path)

        assert client.delete(f"/scans/{scan_id}").status_code == 204
        assert client.get(f"/scans/{scan_id}").status_code == 404
        for d in dirs:
            assert not d.exists()

    def test_delete_is_refused_while_the_scan_is_still_running(self, client, tmp_path):
        _, scan_id, dirs = self._setup(client, tmp_path, status="scanning")

        resp = client.delete(f"/scans/{scan_id}")
        assert resp.status_code == 409
        # The background task is still writing here, so nothing may be removed.
        assert client.get(f"/scans/{scan_id}").status_code == 200
        for d in dirs:
            assert d.exists()

    def test_deleting_the_last_scan_drops_the_project_and_its_zip(self, client, tmp_path):
        project_id, scan_id, _ = self._setup(client, tmp_path)
        zip_path = tmp_path / "uploads" / f"{project_id}.zip"
        assert zip_path.exists()

        client.delete(f"/scans/{scan_id}")

        assert client.get("/projects").json() == []
        assert not zip_path.exists()

    def test_a_project_survives_while_it_still_has_another_scan(self, client, tmp_path):
        from apps.api import database as db_module, models

        project_id, scan_id, _ = self._setup(client, tmp_path)
        db = db_module.SessionLocal()
        db.add(models.Scan(project_id=project_id, status="done"))
        db.commit()
        db.close()

        client.delete(f"/scans/{scan_id}")

        assert [p["id"] for p in client.get("/projects").json()] == [project_id]
        assert (tmp_path / "uploads" / f"{project_id}.zip").exists()
        assert len(client.get(f"/projects/{project_id}/scans").json()) == 1


class TestExportReport:
    """GET /scans/{id}/export. The Markdown side is rendered from the stored
    report.json, so these build a report row pointing at a json file on disk
    rather than running a scan."""

    def _scan_with_report(self, client, tmp_path):
        import json

        from apps.api import database as db_module, models

        upload = client.post("/uploads", files={"file": ("demo.zip", make_zip_bytes(), "application/zip")})
        project_id = upload.json()["id"]

        report_dir = tmp_path / "reports" / "x"
        report_dir.mkdir(parents=True)
        json_path = report_dir / "report.json"
        html_path = report_dir / "report.html"
        json_path.write_text(json.dumps({
            "project": "demo",
            "summary": {},
            "findings": [{
                "rule_id": "r", "messages": ["m"], "cwe": ["CWE-89: x ('SQL Injection')"],
                "source_file": "A.java", "source_line": 1, "sink_file": "A.java", "sink_line": 2,
                "severity": "ERROR", "finding": {"reachable": "yes", "reasoning": "why"},
            }],
        }), encoding="utf-8")
        html_path.write_text("<html>report</html>", encoding="utf-8")

        db = db_module.SessionLocal()
        scan = models.Scan(project_id=project_id, status="done")
        db.add(scan)
        db.flush()
        db.add(models.Report(scan_id=scan.id, html_path=str(html_path), json_path=str(json_path), summary={}))
        db.commit()
        scan_id = scan.id
        db.close()
        return scan_id

    def test_markdown_export_renders_from_the_stored_json(self, client, tmp_path):
        scan_id = self._scan_with_report(client, tmp_path)

        resp = client.get(f"/scans/{scan_id}/export?format=md")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/markdown")
        assert "attachment" in resp.headers["content-disposition"]
        body = resp.text
        assert body.startswith("# 扫描报告 — demo")
        assert "### 1. SQL Injection — `A.java:2`" in body

    def test_markdown_export_honours_the_language(self, client, tmp_path):
        scan_id = self._scan_with_report(client, tmp_path)

        assert client.get(f"/scans/{scan_id}/export?format=md&lang=en").text.startswith("# Scan report")

    def test_html_export_hands_back_the_rendered_page_as_a_download(self, client, tmp_path):
        scan_id = self._scan_with_report(client, tmp_path)

        resp = client.get(f"/scans/{scan_id}/export?format=html")

        assert resp.status_code == 200
        assert resp.text == "<html>report</html>"
        assert "attachment" in resp.headers["content-disposition"]

    def test_a_non_ascii_project_name_survives_in_the_filename(self, client, tmp_path):
        from apps.api.routers.scans import _attachment

        header = _attachment("扫描报告.md")["Content-Disposition"]

        # An ASCII-only browser gets a usable fallback, everyone else gets
        # the real name out of filename*.
        assert "filename=\"" in header
        assert "filename*=UTF-8''" in header

    def test_unknown_format_is_400(self, client, tmp_path):
        scan_id = self._scan_with_report(client, tmp_path)

        assert client.get(f"/scans/{scan_id}/export?format=pdf").status_code == 400

    def test_export_of_a_scan_without_a_report_is_404(self, client):
        assert client.get("/scans/nope/export?format=md").status_code == 404


class TestSettings:
    def test_no_active_config_returns_null(self, client):
        assert client.get("/settings/llm").json() is None

    def test_save_and_read_back_masks_key(self, client):
        client.post("/settings/llm", json={
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "sk-abcdefgh12345678",
            "verify_model": "deepseek-chat",
        })
        cfg = client.get("/settings/llm").json()
        assert cfg["base_url"] == "https://api.deepseek.com/v1"
        assert cfg["verify_model"] == "deepseek-chat"
        assert "abcdefgh1234" not in cfg["api_key_masked"]
        assert cfg["api_key_masked"].startswith("sk-a")

    def test_concurrency_defaults_to_sequential(self, client):
        saved = client.post("/settings/llm", json={"api_key": "sk-x", "verify_model": "m"}).json()

        assert saved["concurrency"] == 1

    def test_concurrency_round_trips(self, client):
        client.post("/settings/llm", json={"api_key": "sk-x", "verify_model": "m", "concurrency": 4})

        assert client.get("/settings/llm").json()["concurrency"] == 4

    def test_concurrency_outside_the_cap_is_rejected(self, client):
        # Capped rather than clamped: silently running 100 at a time because
        # someone typed 100 is how an endpoint gets hammered into a 429.
        for bad in (0, 9, -1):
            resp = client.post("/settings/llm", json={"api_key": "sk-x", "verify_model": "m", "concurrency": bad})
            assert resp.status_code == 422, bad

    def test_test_connection_without_key_fails_fast(self, client):
        resp = client.post("/settings/llm/test", json={"verify_model": "gpt-4o-mini"})
        assert resp.status_code == 200
        assert resp.json()["success"] is False

    def test_saving_a_second_config_keeps_both_but_only_activates_the_new_one(self, client):
        client.post("/settings/llm", json={
            "name": "glm", "base_url": "https://open.bigmodel.cn/api/paas/v4",
            "api_key": "sk-glm", "verify_model": "glm-4-flash",
        })
        second = client.post("/settings/llm", json={
            "name": "deepseek", "base_url": "https://api.deepseek.com/v1",
            "api_key": "sk-ds", "verify_model": "deepseek-chat",
        }).json()

        configs = client.get("/settings/llm/list").json()
        assert {c["name"] for c in configs} == {"glm", "deepseek"}
        by_name = {c["name"]: c for c in configs}
        assert by_name["glm"]["is_active"] is False
        assert by_name["deepseek"]["is_active"] is True
        assert client.get("/settings/llm").json()["id"] == second["id"]

    def test_activate_switches_which_config_is_active(self, client):
        first = client.post("/settings/llm", json={
            "name": "glm", "verify_model": "glm-4-flash",
        }).json()
        client.post("/settings/llm", json={"name": "deepseek", "verify_model": "deepseek-chat"})

        resp = client.post(f"/settings/llm/{first['id']}/activate")
        assert resp.status_code == 200
        assert resp.json()["is_active"] is True
        assert client.get("/settings/llm").json()["id"] == first["id"]

    def test_activate_missing_config_returns_404(self, client):
        resp = client.post("/settings/llm/does-not-exist/activate")
        assert resp.status_code == 404

    def test_delete_config(self, client):
        cfg = client.post("/settings/llm", json={"name": "glm", "verify_model": "glm-4-flash"}).json()
        resp = client.delete(f"/settings/llm/{cfg['id']}")
        assert resp.status_code == 204
        assert client.get("/settings/llm/list").json() == []

    def test_delete_missing_config_returns_404(self, client):
        resp = client.delete("/settings/llm/does-not-exist")
        assert resp.status_code == 404

    def test_deleting_the_active_config_falls_back_to_another_saved_one(self, client):
        first = client.post("/settings/llm", json={"name": "glm", "verify_model": "glm-4-flash"}).json()
        second = client.post("/settings/llm", json={"name": "deepseek", "verify_model": "deepseek-chat"}).json()
        assert second["is_active"] is True  # the one that gets deleted below

        resp = client.delete(f"/settings/llm/{second['id']}")
        assert resp.status_code == 204

        active = client.get("/settings/llm").json()
        assert active["id"] == first["id"]
        assert active["is_active"] is True

    def test_deleting_the_only_config_leaves_none_active(self, client):
        cfg = client.post("/settings/llm", json={"name": "glm", "verify_model": "glm-4-flash"}).json()
        client.delete(f"/settings/llm/{cfg['id']}")
        assert client.get("/settings/llm").json() is None
