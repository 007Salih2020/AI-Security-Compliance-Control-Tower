from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services import evaluate_finding

router = APIRouter(tags=["evaluations"])


@router.post("/evaluate/{finding_id}")
def evaluate(finding_id: str):
    try:
        return evaluate_finding(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
