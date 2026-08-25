"""Shared paths and small helpers used by all Phase 0 scripts."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CANDIDATES_PATH = DATA_DIR / "candidates.json"
VERIFIED_PATH = DATA_DIR / "verified.json"
LLM_CACHE_DIR = DATA_DIR / "llm_cache"
LABELS_PATH = ROOT / "eval" / "labels.json"
PROMPTS_DIR = ROOT / "prompts"


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
