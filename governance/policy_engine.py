from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml

from app.models import GovernanceDecision

POLICY_FILE = Path(__file__).resolve().parent / "policy.yaml"


@lru_cache(maxsize=1)
def load_policy() -> Dict[str, Any]:
    with POLICY_FILE.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def evaluate_action(action: str, context: Dict[str, Any] | None = None) -> GovernanceDecision:
    policy = load_policy()
    context = context or {}

    if action == "export_sensitive_data" and context.get("contains_sensitive_data", True):
        return GovernanceDecision(
            action=action,
            decision="deny",
            matched_rule="GOV-004",
            reason="The request involves sensitive data and policy blocks external export.",
            policy_name=policy.get("policy_name", "Unnamed Policy"),
            context=context,
        )

    for rule in policy.get("rules", []):
        if action in rule.get("actions", []):
            return GovernanceDecision(
                action=action,
                decision=rule["decision"],
                matched_rule=rule["rule_id"],
                reason=rule["reason"],
                policy_name=policy.get("policy_name", "Unnamed Policy"),
                context=context,
            )

    return GovernanceDecision(
        action=action,
        decision=policy.get("default_decision", "require_approval"),
        matched_rule="DEFAULT",
        reason="No explicit policy rule matched; default governance handling was applied.",
        policy_name=policy.get("policy_name", "Unnamed Policy"),
        context=context,
    )
