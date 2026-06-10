from __future__ import annotations

from fastapi import APIRouter

from app.models import PolicyCheckRequest
from app.services import policy_check

router = APIRouter(tags=["governance"])


@router.post("/policy/check")
def check_policy(request: PolicyCheckRequest):
    return policy_check(action=request.action, context=request.context)
