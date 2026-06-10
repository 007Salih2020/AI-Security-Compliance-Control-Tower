from __future__ import annotations

from app.models import NormalizedFinding, RiskAssessment

SEVERITY_WEIGHTS = {"Low": 10, "Medium": 20, "High": 30, "Critical": 45}
CRITICALITY_WEIGHTS = {"low": 0, "medium": 5, "high": 10, "critical": 15}
COMPLIANCE_WEIGHTS = {"low": 5, "medium": 10, "high": 10}
EXPLOITABILITY_WEIGHTS = {"low": 5, "medium": 10, "high": 10}
DATA_SENSITIVITY_WEIGHTS = {"public": 0, "internal": 5, "confidential": 10, "regulated": 15}
REMEDIATION_WEIGHTS = {"open": 5, "planned": 3, "in_progress": 1, "mitigated": -10}


def score_finding(finding: NormalizedFinding) -> RiskAssessment:
    score = 0
    score += SEVERITY_WEIGHTS.get(finding.severity, 0)
    score += CRITICALITY_WEIGHTS.get(finding.asset_criticality, 0)
    score += 10 if finding.internet_exposure else 0
    score += COMPLIANCE_WEIGHTS.get(finding.compliance_relevance, 0)
    score += EXPLOITABILITY_WEIGHTS.get(finding.exploitability, 0)
    score += DATA_SENSITIVITY_WEIGHTS.get(finding.data_sensitivity, 0)
    score += 10 if finding.ai_agent_involved else 0
    score += REMEDIATION_WEIGHTS.get(finding.remediation_status, 0)
    score = max(0, min(100, score))

    if score >= 90:
        rating = "Critical"
    elif score >= 70:
        rating = "High"
    elif score >= 35:
        rating = "Medium"
    else:
        rating = "Low"

    business_impact = _business_impact(finding, rating)
    reasoning = (
        f"{finding.severity} severity finding on a {finding.asset_criticality} criticality asset, "
        f"compliance relevance {finding.compliance_relevance}, exploitability {finding.exploitability}, "
        f"data sensitivity {finding.data_sensitivity}, internet exposure {finding.internet_exposure}, "
        f"AI-agent involvement {finding.ai_agent_involved}."
    )
    return RiskAssessment(
        risk_score=score,
        risk_rating=rating,
        risk_reasoning=reasoning,
        business_impact=business_impact,
    )


def _business_impact(finding: NormalizedFinding, rating: str) -> str:
    if rating == "Critical":
        return (
            f"{finding.title} creates immediate operational and audit risk because it affects "
            f"{finding.resource_name} with {finding.data_sensitivity} data exposure potential."
        )
    if rating == "High":
        return (
            f"{finding.title} can materially increase incident likelihood and weaken compliance posture for "
            f"{finding.resource_name}."
        )
    if rating == "Medium":
        return (
            f"{finding.title} should be remediated to reduce control gaps and future security debt."
        )
    return f"{finding.title} is lower impact but still tracked for remediation hygiene."
