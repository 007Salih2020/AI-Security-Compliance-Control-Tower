from __future__ import annotations

from typing import List

from app.models import ModelInventoryRecord


def score_model_risk(model: ModelInventoryRecord) -> ModelInventoryRecord:
    score = 0
    reasoning: List[str] = []
    actions: List[str] = []
    missing_fields: List[str] = []

    def add(points: int, reason: str, action: str | None = None) -> None:
        nonlocal score
        score += points
        reasoning.append(reason)
        if action and action not in actions:
            actions.append(action)

    if model.owner.lower() == "unknown":
        add(20, "Missing accountable owner.", "Assign a business and technical owner.")
        missing_fields.append("owner")
    if model.use_case.lower() == "unknown":
        add(10, "Use case is not documented.", "Document the business use case.")
        missing_fields.append("use_case")
    if model.environment.lower() == "production":
        add(15, "Production deployment increases blast radius.")
    if model.internet_accessible:
        add(15, "Internet-accessible endpoint increases exposure.", "Review public exposure and restrict access.")
    if model.processes_personal_data:
        add(15, "Processes personal data.", "Validate privacy controls and lawful processing basis.")
    if model.processes_confidential_data:
        add(20, "Processes confidential or regulated data.", "Review data classification, minimization, and encryption controls.")
    if not model.logging_enabled:
        add(10, "Logging is disabled.", "Enable monitoring and audit logs.")
        missing_fields.append("logging")
    if not model.content_filtering_enabled:
        add(15, "Content filtering is disabled.", "Enable content filtering or compensating safeguards.")
        missing_fields.append("content_filtering")
    if not model.evaluation_available:
        add(15, "Evaluation evidence is missing.", "Run quality and safety evaluations.")
        missing_fields.append("evaluation")
    if not model.red_team_tested:
        add(10, "Red-team evidence is missing.", "Perform adversarial testing and attach the results.")
        missing_fields.append("red_team")
    if model.used_by_agent:
        add(15, "Model is used by an autonomous or semi-autonomous agent.", "Apply deterministic policy checks to all agent actions.")
    if model.public_endpoint:
        add(10, "Endpoint is public and not on private networking.")
    if any(term in model.use_case.lower() for term in ["fraud", "incident", "approval", "decision"]):
        add(10, "Use case is materially impactful to operations or customers.")
    if model.approval_status != "approved":
        add(20, "Production-grade governance approval is incomplete.", "Obtain governance approval before continued production use.")
        missing_fields.append("approval_status")
    if model.model_version.startswith("2024"):
        add(5, "Model version appears older than current internal baseline.", "Review model version currency and refresh cadence.")

    score = min(100, score)
    if score >= 90:
        tier = "Critical"
    elif score >= 80:
        tier = "High"
    elif score >= 45:
        tier = "Medium"
    else:
        tier = "Low"

    model.risk_score = score
    model.risk_tier = tier
    model.risk_reasoning = " ".join(reasoning) if reasoning else "No material risk indicators were detected."
    model.recommended_actions = actions
    model.missing_fields = sorted(set(missing_fields))
    model.governance_review_required = bool(model.missing_fields) or model.risk_tier in {"High", "Critical"}
    return model
