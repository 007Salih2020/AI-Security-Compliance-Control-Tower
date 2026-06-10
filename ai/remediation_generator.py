from __future__ import annotations

from typing import List

from app.models import ModelInventoryRecord, NormalizedFinding


def remediation_steps_for_finding(finding: NormalizedFinding) -> List[str]:
    steps = [step.strip() for step in finding.remediation.split(",") if step.strip()]
    if finding.severity in {"High", "Critical"}:
        steps.insert(0, "Assign an accountable owner and remediation deadline within the current sprint.")
    return steps


def remediation_steps_for_model(model: ModelInventoryRecord) -> List[str]:
    steps = list(model.recommended_actions)
    if model.owner.lower() == "unknown":
        steps.append("Block production expansion until ownership is assigned.")
    if not model.logging_enabled:
        steps.append("Enable model and agent telemetry to meet logging evidence expectations.")
    if model.approval_status != "approved":
        steps.append("Route the deployment through the AI governance approval workflow.")
    return list(dict.fromkeys(steps))
