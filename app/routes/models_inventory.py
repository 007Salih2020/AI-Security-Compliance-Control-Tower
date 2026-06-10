from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models import OwnerUpdateRequest
from models_inventory.azure_discovery import AzureDiscoveryError
from app.services import (
    analyze_model,
    discover_and_register_models,
    evaluate_model,
    generate_model_evidence,
    get_high_risk_models,
    get_model_or_raise,
    get_unknown_owner_models,
    list_models,
    rescore_registered_models,
    score_model,
    update_model_owner,
)

router = APIRouter(tags=["models"])


@router.get("/models")
def models():
    return list_models()


@router.post("/models/discover")
def discover(source: str = "local"):
    try:
        return discover_and_register_models(source=source)
    except AzureDiscoveryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/models/{model_id}/owner")
def update_owner(model_id: str, request: OwnerUpdateRequest):
    try:
        return update_model_owner(
            model_id=model_id,
            owner=request.owner,
            business_unit=request.business_unit,
            use_case=request.use_case,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/models/{model_id}/risk")
def risk(model_id: str):
    try:
        return score_model(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/models/{model_id}/evaluate")
def evaluate(model_id: str):
    try:
        return evaluate_model(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/models/{model_id}/evidence")
def evidence(model_id: str):
    try:
        return generate_model_evidence(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/models/unknown-owners")
def unknown_owners():
    return get_unknown_owner_models()


@router.get("/models/high-risk")
def high_risk():
    return get_high_risk_models()


@router.post("/models/rescore")
def rescore():
    return rescore_registered_models()


@router.get("/models/{model_id}")
def model(model_id: str):
    try:
        return get_model_or_raise(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
