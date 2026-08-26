"""
Shared pytest fixtures. The scripts under scripts/ are numbered
(01_scan.py, 02_verify.py, ...) so they aren't valid `import` module
names -- this loads them by file path instead.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


def _load_module(filename: str):
    # scripts/common.py is imported with a plain `from common import ...`
    # inside the numbered scripts, so scripts/ must be on sys.path first.
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))

    module_name = filename.replace(".py", "").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def scan_module():
    return _load_module("01_scan.py")
