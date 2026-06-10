from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.database import get_db
from app.services import generate_finding_evidence

router = APIRouter(tags=["evidence"])


@router.post("/evidence/{finding_id}")
def evidence(finding_id: str):
    try:
        return generate_finding_evidence(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reports")
def reports():
    return get_db().get_reports()
