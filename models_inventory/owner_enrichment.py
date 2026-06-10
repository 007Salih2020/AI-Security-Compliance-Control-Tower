from __future__ import annotations

from app.database import get_db
from app.models import ModelInventoryRecord, OwnerUpdateRequest
from models_inventory.model_risk_scoring import score_model_risk


def set_model_owner(model_id: str, request: OwnerUpdateRequest) -> ModelInventoryRecord:
    db = get_db()
    model = db.get_model(model_id)
    if model is None:
        raise ValueError(f"Model {model_id} was not found.")

    model.owner = request.owner
    model.business_unit = request.business_unit
    model.use_case = request.use_case
    if model.approval_status == "needs_review":
        model.approval_status = "pending"
    model = score_model_risk(model)
    return db.save_model(model)
