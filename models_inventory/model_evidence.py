from __future__ import annotations

from app.database import get_db
from evidence.evidence_builder import build_model_evidence


def generate_model_evidence(model_id: str):
    model = get_db().get_model(model_id)
    if model is None:
        raise ValueError(f"Model {model_id} was not found.")
    return build_model_evidence(model)
