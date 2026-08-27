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
