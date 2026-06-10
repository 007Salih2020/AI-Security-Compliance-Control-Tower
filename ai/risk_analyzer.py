from __future__ import annotations

from typing import List

from ai.azure_openai_client import AzureOpenAIWrapper
from ai.prompts import build_finding_prompt, build_model_prompt
from ai.remediation_generator import remediation_steps_for_finding, remediation_steps_for_model
from app.models import AIAnalysis, ModelInventoryRecord, NormalizedFinding


def analyze_finding(finding: NormalizedFinding) -> AIAnalysis:
    client = AzureOpenAIWrapper()
    if client.available():
        try:
            return client.generate_structured(build_finding_prompt(finding), AIAnalysis)
        except Exception:
            pass
    return _mock_finding_analysis(finding)


def analyze_model(model: ModelInventoryRecord) -> AIAnalysis:
    client = AzureOpenAIWrapper()
    if client.available():
        try:
            return client.generate_structured(build_model_prompt(model), AIAnalysis)
        except Exception:
            pass
    return _mock_model_analysis(model)


def _frameworks_summary(control_ids: List[str]) -> str:
    return ", ".join(control_ids) if control_ids else "No mapped controls"


def _mock_finding_analysis(finding: NormalizedFinding) -> AIAnalysis:
    control_ids = [control.control_id for control in finding.mapped_controls]
    return AIAnalysis(
        target_id=finding.finding_id,
        target_type="finding",
        technical_explanation=(
            f"{finding.title} affects {finding.resource_name} in {finding.service}. "
            f"The issue is currently {finding.status} and exposes a {finding.data_sensitivity} workload."
        ),
        business_impact=(
            f"If unresolved, {finding.title.lower()} can increase incident response cost, audit scrutiny, "
            f"and operational disruption for the owning team."
        ),
        compliance_impact=(
            f"The finding maps to {_frameworks_summary(control_ids)} and weakens demonstrable control coverage."
        ),
        likelihood_reasoning=(
            f"Likelihood is elevated because exploitability is {finding.exploitability} and internet exposure is {finding.internet_exposure}."
        ),
        severity_reasoning=(
            f"The risk score of {finding.risk_score} is consistent with {finding.severity} severity and {finding.asset_criticality} asset criticality."
        ),
        remediation_plan=remediation_steps_for_finding(finding),
        executive_summary=(
            f"{finding.finding_id} represents a {finding.risk_rating.lower()} risk requiring owner-backed remediation and evidence capture."
        ),
        audit_evidence_summary=(
            f"Evidence should include configuration state, remediation ticket, and proof of control coverage for {finding.finding_id}."
        ),
        suggested_owner="Cloud Security" if "Azure" in finding.provider else "DevSecOps",
        suggested_priority="P1" if finding.risk_rating in {"High", "Critical"} else "P2",
    )


def _mock_model_analysis(model: ModelInventoryRecord) -> AIAnalysis:
    control_ids = [control.control_id for control in model.compliance_mappings]
    return AIAnalysis(
        target_id=model.model_inventory_id,
        target_type="model",
        technical_explanation=(
            f"{model.model_name} is deployed as {model.deployment_name} on {model.platform}. "
            f"It currently has risk tier {model.risk_tier} with score {model.risk_score}."
        ),
        business_impact=(
            f"The model supports {model.application_name} and could create governance, privacy, or operational risk "
            f"if its missing controls are not closed."
        ),
        compliance_impact=(
            f"The model maps to {_frameworks_summary(control_ids)} and currently has approval status {model.approval_status}."
        ),
        likelihood_reasoning=(
            f"Likelihood is driven by data classification {model.data_classification}, internet accessibility {model.internet_accessible}, "
            f"and agent usage {model.used_by_agent}."
        ),
        severity_reasoning=(
            f"Severity is elevated because missing fields are {', '.join(model.missing_fields) or 'none'} and recommended actions total {len(model.recommended_actions)}."
        ),
        remediation_plan=remediation_steps_for_model(model),
        executive_summary=(
            f"{model.model_inventory_id} is a {model.risk_tier.lower()}-tier AI asset that requires governance evidence before broader production use."
        ),
        audit_evidence_summary=(
            f"Evidence should capture owner assignment, approval state, logging, evaluations, and control mappings for {model.model_inventory_id}."
        ),
        suggested_owner=model.owner if model.owner.lower() != "unknown" else "AI Governance Office",
        suggested_priority="P1" if model.risk_tier in {"High", "Critical"} else "P2",
    )
