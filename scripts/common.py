"""Shared paths and small helpers used by all Phase 0 scripts.

The actual implementation now lives in scanner/common.py so apps/api can
import it too (scripts/ is only importable via the importlib file-path
trick used in tests/conftest.py). This module just re-exports it so the
existing `from common import ...` calls inside the numbered scripts keep
working unchanged.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.common import (  # noqa: F401
    CANDIDATES_PATH,
    DATA_DIR,
    DB_PATH,
    LABELS_PATH,
    LLM_CACHE_DIR,
    PROMPTS_DIR,
    REPORTS_DIR,
    ROOT,
    UPLOADS_DIR,
    VERIFIED_PATH,
    WORKSPACES_DIR,
    ensure_data_dir,
    load_default_configs,
    load_json,
    sha256,
    write_json,
)
