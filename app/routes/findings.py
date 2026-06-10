from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models import IngestRequest
from app.services import get_finding_or_raise, ingest_findings, list_findings

router = APIRouter(tags=["findings"])


@router.get("/findings")
def get_findings():
    return list_findings()


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    try:
        return get_finding_or_raise(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/ingest")
def ingest(request: IngestRequest):
    try:
        return ingest_findings(request.file)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
