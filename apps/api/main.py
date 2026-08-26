"""FastAPI entrypoint. Run with:

    uvicorn apps.api.main:app --reload --port 8000

Serves the API and the single-page frontend (apps/web/) from one process —
simpler than the two-terminal setup in docs/framework.md section 6 since
apps/web has no build step to run separately.
"""
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from apps.api.database import Base, SessionLocal, engine
from apps.api.routers import scans, settings, uploads
from scanner.common import ROOT, ensure_data_dir

load_dotenv(ROOT / ".env")


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_data_dir()
    Base.metadata.create_all(bind=engine)
    _seed_llm_config_from_env()
    yield


app = FastAPI(title="sast-local API", lifespan=lifespan)

app.include_router(uploads.router)
app.include_router(scans.router)
app.include_router(settings.router)


def _seed_llm_config_from_env() -> None:
    """If no LLMConfig exists yet but OPENAI_API_KEY is set in .env, seed one
    so scans work immediately without a trip to /settings first."""
    from apps.api import models

    db = SessionLocal()
    try:
        if db.query(models.LLMConfig).count() > 0:
            return
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return
        db.add(models.LLMConfig(
            name="from .env",
            provider_type="openai_compatible",
            base_url=os.environ.get("OPENAI_BASE_URL"),
            api_key=api_key,
            verify_model=os.environ.get("OPENAI_VERIFY_MODEL", "gpt-4o-mini"),
            is_active=True,
        ))
        db.commit()
    finally:
        db.close()


WEB_DIR = ROOT / "apps" / "web"
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
