from __future__ import annotations

from pathlib import Path
from typing import List

from app.config import get_settings
from app.database import get_db
from app.models import DemoSummary, GovernanceDecision, ModelInventoryRecord, NormalizedFinding
from evidence.evidence_builder import write_executive_summary_report


def build_demo_summary() -> DemoSummary:
    db = get_db()
    findings = db.get_findings()
    models = db.get_models()
    decisions = db.get_governance_decisions()
    reports = db.get_reports()

    passed_findings = 0
    total_evaluated_findings = 0
    for finding in findings:
        if finding.evaluations:
            total_evaluated_findings += 1
            if all(result.pass_fail for result in finding.evaluations):
                passed_findings += 1

    ciso_message = (
        "ControlLens AI gives us a live inventory of AI/LLM deployments, identifies ownership gaps, "
        "scores model risk, maps cloud and AI risks to controls, governs AI actions, evaluates AI output, "
        "and produces audit-ready evidence."
    )
    return DemoSummary(
        findings_ingested=len(findings),
        models_discovered=len(models),
        models_missing_owners=len([model for model in models if model.owner.lower() == "unknown"]),
        high_risk_models=len([model for model in models if model.risk_tier in {"High", "Critical"}]),
        critical_findings=len([finding for finding in findings if finding.risk_rating == "Critical"]),
        controls_mapped=sum(len(finding.mapped_controls) for finding in findings)
        + sum(len(model.compliance_mappings) for model in models),
        analyses_generated=len([finding for finding in findings if finding.ai_analysis]),
        model_risk_assessments_generated=len(models),
        evaluations_passed=f"{passed_findings}/{max(total_evaluated_findings, 1)}",
        governance_denials=len([decision for decision in decisions if decision.decision == "deny"]),
        evidence_reports_generated=len(findings) + len(models),
        ciso_message=ciso_message,
    )


def generate_executive_summary_markdown() -> str:
    db = get_db()
    findings = db.get_findings()
    models = db.get_models()
    decisions = db.get_governance_decisions()
    summary = build_demo_summary()
    return _render_markdown(summary, findings, models, decisions)


def save_executive_summary() -> Path:
    markdown = generate_executive_summary_markdown()
    return write_executive_summary_report(markdown)


def _render_markdown(
    summary: DemoSummary,
    findings: List[NormalizedFinding],
    models: List[ModelInventoryRecord],
    decisions: List[GovernanceDecision],
) -> str:
    top_findings = sorted(findings, key=lambda item: item.risk_score, reverse=True)[:5]
    top_models = sorted(models, key=lambda item: item.risk_score, reverse=True)[:5]
    lines = [
        "# ControlLens AI Executive Summary",
        "",
        "## CISO Message",
        summary.ciso_message,
        "",
        "## Risk Snapshot",
        f"- Security findings ingested: {summary.findings_ingested}",
        f"- AI/LLM models discovered: {summary.models_discovered}",
        f"- Models missing owners: {summary.models_missing_owners}",
        f"- High-risk AI models: {summary.high_risk_models}",
        f"- Critical security findings: {summary.critical_findings}",
        f"- Governance denials: {summary.governance_denials}",
        "",
        "## Top Security Findings",
    ]
    for finding in top_findings:
        lines.append(f"- {finding.finding_id}: {finding.title} ({finding.risk_rating}, score {finding.risk_score})")
    lines.extend(["", "## Top AI Model Risks"])
    for model in top_models:
        lines.append(f"- {model.model_inventory_id}: {model.model_name} ({model.risk_tier}, score {model.risk_score})")
    lines.extend(["", "## Governance Decisions"])
    for decision in decisions[-5:]:
        lines.append(f"- {decision.action}: {decision.decision} via {decision.matched_rule} ({decision.reason})")
    lines.extend(
        [
            "",
            "## Compliance Positioning",
            "- ISO 27001 A.12.4: Logging coverage is explicitly assessed for cloud assets and AI systems, with evidence attached to findings and model records.",
            "- ISO 27001 A.5.1: AI governance policies are enforced through approval checks, owner assignment, and deterministic policy decisions for agent actions.",
        ]
    )
    return "\n".join(lines) + "\n"
