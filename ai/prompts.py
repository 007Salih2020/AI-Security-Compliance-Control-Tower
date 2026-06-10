from __future__ import annotations

from app.models import ModelInventoryRecord, NormalizedFinding


def build_finding_prompt(finding: NormalizedFinding) -> str:
    return (
        "Analyze the following security finding in JSON form with fields for technical_explanation, "
        "business_impact, compliance_impact, likelihood_reasoning, severity_reasoning, remediation_plan, "
        "executive_summary, audit_evidence_summary, suggested_owner, and suggested_priority.\n\n"
        f"Finding ID: {finding.finding_id}\n"
        f"Title: {finding.title}\n"
        f"Description: {finding.description}\n"
        f"Severity: {finding.severity}\n"
        f"Risk score: {finding.risk_score}\n"
        f"Mapped controls: {[control.control_id for control in finding.mapped_controls]}\n"
        f"Remediation guidance: {finding.remediation}\n"
    )


def build_model_prompt(model: ModelInventoryRecord) -> str:
    return (
        "Analyze the following AI model governance risk in JSON form with fields for technical_explanation, "
        "business_impact, compliance_impact, likelihood_reasoning, severity_reasoning, remediation_plan, "
        "executive_summary, audit_evidence_summary, suggested_owner, and suggested_priority.\n\n"
        f"Model ID: {model.model_inventory_id}\n"
        f"Model name: {model.model_name}\n"
        f"Deployment: {model.deployment_name}\n"
        f"Environment: {model.environment}\n"
        f"Risk score: {model.risk_score}\n"
        f"Approval status: {model.approval_status}\n"
        f"Owner: {model.owner}\n"
        f"Missing fields: {model.missing_fields}\n"
        f"Mapped controls: {[control.control_id for control in model.compliance_mappings]}\n"
    )
