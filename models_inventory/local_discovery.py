from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.config import get_settings
from app.models import ModelInventoryRecord


def _load_json(file_path: Path):
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_model_file(file_path: Path) -> List[ModelInventoryRecord]:
    payload = _load_json(file_path)
    records: List[ModelInventoryRecord] = []
    for item in payload:
        item["public_endpoint"] = bool(item.get("internet_accessible")) and not bool(item.get("private_network_enabled"))
        records.append(ModelInventoryRecord.model_validate(item))
    return records


def discover_local_models() -> List[ModelInventoryRecord]:
    settings = get_settings()
    files = [
        settings.samples_dir / "azure_openai_deployments.json",
        settings.samples_dir / "azure_ml_models.json",
        settings.samples_dir / "ai_endpoints.json",
    ]
    models: List[ModelInventoryRecord] = []
    for file_path in files:
        models.extend(_load_model_file(file_path))
    return models
