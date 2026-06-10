from __future__ import annotations

import json
from typing import List

from app.database import get_db
from app.models import ModelInventoryRecord
from compliance.control_mapper import map_model_to_controls
from models_inventory.azure_discovery import AzureDiscoveryResult, discover_models_via_azure
from models_inventory.local_discovery import discover_local_models
from models_inventory.model_risk_scoring import score_model_risk


def discover_models(source: str = "local") -> List[ModelInventoryRecord]:
    if source == "azure":
        result = discover_models_via_azure(force_live=True)
        models = result.models
    else:
        models = discover_local_models()

    prepared: List[ModelInventoryRecord] = []
    for model in models:
        model = score_model_risk(model)
        model.compliance_mappings = map_model_to_controls(model)
        prepared.append(model)
    return prepared


def register_discovered_models(source: str = "local", replace_existing: bool = False) -> List[ModelInventoryRecord]:
    models = discover_models(source=source)
    if replace_existing:
        return get_db().replace_models(models)
    return get_db().save_models(models)


def discover_models_with_metadata(source: str = "local") -> AzureDiscoveryResult | None:
    if source != "azure":
        return None
    return discover_models_via_azure(force_live=True)


def list_models() -> List[ModelInventoryRecord]:
    return get_db().get_models()


def rescore_models() -> List[ModelInventoryRecord]:
    db = get_db()
    rescored: List[ModelInventoryRecord] = []
    for model in db.get_models():
        model = score_model_risk(model)
        model.compliance_mappings = map_model_to_controls(model)
        rescored.append(db.save_model(model))
    return rescored


def unknown_owner_models() -> List[ModelInventoryRecord]:
    return [model for model in get_db().get_models() if model.owner.lower() == "unknown"]


def high_risk_models() -> List[ModelInventoryRecord]:
    return [model for model in get_db().get_models() if model.risk_tier in {"High", "Critical"}]


def export_models(format_name: str = "json") -> str:
    models = [model.model_dump(mode="json") for model in get_db().get_models()]
    if format_name == "json":
        return json.dumps(models, indent=2)
    raise ValueError(f"Unsupported export format: {format_name}")
