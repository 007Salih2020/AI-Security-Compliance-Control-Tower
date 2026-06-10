from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parent.parent
    data_store = tmp_path / "store.json"
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("DATA_STORE_PATH", str(data_store))
    monkeypatch.setenv("REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("SAMPLES_DIR", str(root / "samples"))
    monkeypatch.setenv("ENABLE_AZURE_DISCOVERY", "false")
    yield
