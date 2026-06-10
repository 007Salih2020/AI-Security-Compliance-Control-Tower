from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services import analyze_finding

router = APIRouter(tags=["analysis"])


@router.post("/analyze/{finding_id}")
def analyze(finding_id: str):
    try:
        return analyze_finding(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
