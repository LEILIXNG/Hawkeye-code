"""Shared paths and small helpers used across scanner/ and scripts/."""
import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULESET_PATH = ROOT / "rules" / "ruleset.yml"
DATA_DIR = ROOT / "data"
CANDIDATES_PATH = DATA_DIR / "candidates.json"
VERIFIED_PATH = DATA_DIR / "verified.json"
LLM_CACHE_DIR = DATA_DIR / "llm_cache"
LABELS_PATH = ROOT / "eval" / "labels.json"
PROMPTS_DIR = ROOT / "prompts"
UPLOADS_DIR = DATA_DIR / "uploads"
WORKSPACES_DIR = DATA_DIR / "workspaces"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "db.sqlite3"


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_default_configs() -> list[str]:
    """Reads rules/ruleset.yml and resolves each entry to an absolute path,
    so callers can pass the result straight to `semgrep --config` regardless
    of their own current working directory."""
    ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
    return [str(ROOT / c) for c in ruleset["configs"]]
