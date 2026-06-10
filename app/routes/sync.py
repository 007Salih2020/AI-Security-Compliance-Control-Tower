from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models import SecuritySyncRequest
from app.services import refresh_live_security_findings
from scanners.azure_security_sync import AzureSecuritySyncError

router = APIRouter(tags=["sync"])


@router.post("/sync/security/azure")
def sync_security_azure(request: SecuritySyncRequest | None = None):
    payload = request or SecuritySyncRequest()
    try:
        return refresh_live_security_findings(
            lookback_hours=payload.lookback_hours,
            include_policy_states=payload.include_policy_states,
            include_activity_log=payload.include_activity_log,
            include_prowler=payload.include_prowler,
            include_github_artifacts=payload.include_github_artifacts,
            replace_existing=payload.replace_existing,
            preserve_ai_governance=payload.preserve_ai_governance,
            generate_evidence=payload.generate_evidence,
            evidence_limit=payload.evidence_limit,
        )
    except AzureSecuritySyncError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
