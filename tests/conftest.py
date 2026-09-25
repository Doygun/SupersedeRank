from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import paths

@pytest.fixture(scope="session")
def data_profile_dir() -> Path:
    return paths.DATA_PROFILE_DIR

@pytest.fixture(scope="session")
def history_dir() -> Path:
    if not any(paths.NVD_HISTORY_DIR.glob("*.json")):
        pytest.skip(f"NVD History verisi yok: {paths.NVD_HISTORY_DIR}")
    return paths.NVD_HISTORY_DIR
