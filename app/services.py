from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from ai.executive_summary import build_demo_summary, save_executive_summary
from ai.risk_analyzer import analyze_finding as generate_finding_analysis
from ai.risk_analyzer import analyze_model as generate_model_analysis
from app.config import get_settings
from app.database import get_db
from app.models import (
    DemoSummary,
    GovernanceDecision,
    ModelInventoryRecord,
    NormalizedFinding,
    OwnerUpdateRequest,
    SecuritySyncSummary,
)
from compliance.control_mapper import map_finding_to_controls
from evals.local_evaluators import evaluate_finding_analysis, evaluate_model_analysis
from evidence.evidence_builder import build_finding_evidence, build_model_evidence
from governance.policy_engine import evaluate_action
from models_inventory.owner_enrichment import set_model_owner
from models_inventory.model_risk_scoring import score_model_risk
from models_inventory.registry import discover_models, high_risk_models, register_discovered_models, rescore_models, unknown_owner_models
from risk.scoring import score_finding
from scanners.azure_security_sync import collect_live_security_findings
from scanners.normalizer import load_demo_findings, load_findings_from_file


def reset_state(clear_reports: bool = True) -> None:
    db = get_db()
    db.reset()
    if clear_reports:
        reports_dir = get_settings().reports_dir
        for path in reports_dir.iterdir():
            if path.name == ".gitkeep":
                continue
            if path.is_file():
                path.unlink()


def ingest_findings(file_path: str | Path) -> List[NormalizedFinding]:
    db = get_db()
    findings = load_findings_from_file(file_path)
    processed = _process_findings(findings)
    return db.save_findings(processed)


def ingest_demo() -> List[NormalizedFinding]:
    findings = load_demo_findings()
    processed = _process_findings(findings)
    return get_db().save_findings(processed)


def list_findings() -> List[NormalizedFinding]:
    return get_db().get_findings()


def get_finding_or_raise(finding_id: str) -> NormalizedFinding:
    finding = get_db().get_finding(finding_id)
    if finding is None:
        raise ValueError(f"Finding {finding_id} was not found.")
    return finding


def analyze_finding(finding_id: str) -> NormalizedFinding:
    db = get_db()
    finding = get_finding_or_raise(finding_id)
    finding.ai_analysis = generate_finding_analysis(finding)
    db.save_finding(finding)
    return finding


def evaluate_finding(finding_id: str) -> NormalizedFinding:
    db = get_db()
    finding = get_finding_or_raise(finding_id)
    if finding.ai_analysis is None:
        finding.ai_analysis = generate_finding_analysis(finding)
    finding.evaluations = evaluate_finding_analysis(finding)
    finding.trusted_analysis = all(result.pass_fail for result in finding.evaluations)
    db.save_finding(finding)
    return finding


def generate_finding_evidence(finding_id: str):
    finding = get_finding_or_raise(finding_id)
    return build_finding_evidence(finding)


def discover_and_register_models(source: str = "local", replace_existing: bool | None = None) -> List[ModelInventoryRecord]:
    if replace_existing is None:
        replace_existing = source == "azure"
    return register_discovered_models(source=source, replace_existing=replace_existing)


def list_models() -> List[ModelInventoryRecord]:
    return get_db().get_models()


def get_model_or_raise(model_id: str) -> ModelInventoryRecord:
    model = get_db().get_model(model_id)
    if model is None:
        raise ValueError(f"Model {model_id} was not found.")
    return model


def analyze_model(model_id: str) -> ModelInventoryRecord:
    db = get_db()
    model = get_model_or_raise(model_id)
    model.ai_analysis = generate_model_analysis(model)
    db.save_model(model)
    return model


def evaluate_model(model_id: str) -> ModelInventoryRecord:
    db = get_db()
    model = get_model_or_raise(model_id)
    if model.ai_analysis is None:
        model.ai_analysis = generate_model_analysis(model)
    model.evaluations = evaluate_model_analysis(model)
    model.trusted_analysis = all(result.pass_fail for result in model.evaluations)
    db.save_model(model)
    return model


def score_model(model_id: str) -> ModelInventoryRecord:
    db = get_db()
    model = get_model_or_raise(model_id)
    model = score_model_risk(model)
    db.save_model(model)
    return model


def generate_model_evidence(model_id: str):
    model = get_model_or_raise(model_id)
    return build_model_evidence(model)


def update_model_owner(model_id: str, owner: str, business_unit: str, use_case: str) -> ModelInventoryRecord:
    request = OwnerUpdateRequest(owner=owner, business_unit=business_unit, use_case=use_case)
    return set_model_owner(model_id, request)


def rescore_registered_models() -> List[ModelInventoryRecord]:
    return rescore_models()


def get_unknown_owner_models() -> List[ModelInventoryRecord]:
    return unknown_owner_models()


def get_high_risk_models() -> List[ModelInventoryRecord]:
    return high_risk_models()


def policy_check(action: str, context: Dict[str, object] | None = None, persist: bool = True) -> GovernanceDecision:
    decision = evaluate_action(action, context=context or {})
    if persist:
        get_db().save_governance_decision(decision)
    return decision


def replay_governance_trace() -> List[GovernanceDecision]:
    settings = get_settings()
    trace_path = settings.samples_dir / "risky_ai_agent_trace.json"
    with trace_path.open("r", encoding="utf-8") as handle:
        trace = json.load(handle)

    decisions: List[GovernanceDecision] = []
    for action in trace.get("actions", []):
        decisions.append(
            policy_check(
                action=action["action"],
                context={
                    "agent_name": trace.get("agent_name"),
                    "target": action.get("target"),
                    "environment": trace.get("environment"),
                    "contains_sensitive_data": action.get("sensitive", False),
                },
            )
        )
    decisions.append(
        policy_check(
            action="approve_model",
            context={"requested_by": "automation", "environment": "production"},
        )
    )
    return decisions


def ensure_demo_state() -> None:
    db = get_db()
    if not db.get_findings():
        ingest_demo()
    if not db.get_models():
        discover_and_register_models(source="local")


def refresh_live_azure_models(generate_evidence: bool = True) -> List[ModelInventoryRecord]:
    models = discover_and_register_models(source="azure", replace_existing=True)
    if generate_evidence:
        for model in models:
            analyze_model(model.model_inventory_id)
            evaluate_model(model.model_inventory_id)
            generate_model_evidence(model.model_inventory_id)
    return models


def refresh_live_security_findings(
    lookback_hours: int | None = None,
    include_policy_states: bool = True,
    include_activity_log: bool = True,
    include_prowler: bool = True,
    include_github_artifacts: bool = True,
    replace_existing: bool = True,
    preserve_ai_governance: bool = True,
    generate_evidence: bool = True,
    evidence_limit: int = 25,
) -> SecuritySyncSummary:
    collected = collect_live_security_findings(
        lookback_hours=lookback_hours,
        include_policy_states=include_policy_states,
        include_activity_log=include_activity_log,
        include_prowler=include_prowler,
        include_github_artifacts=include_github_artifacts,
    )
    processed = _process_findings(collected.findings)
    preserved_categories = ["AI Governance"] if preserve_ai_governance else []

    if replace_existing and processed:
        saved = get_db().replace_findings(processed, preserve_categories=preserved_categories)
    elif replace_existing and not processed:
        saved = []
        collected.warnings.append("Live security sync returned no findings, so the existing finding registry was left unchanged.")
    else:
        saved = get_db().save_findings(processed)

    if generate_evidence:
        prioritized = sorted(saved, key=lambda finding: finding.risk_score, reverse=True)
        evidence_targets = prioritized[: max(0, evidence_limit)]
        for finding in evidence_targets:
            analyze_finding(finding.finding_id)
            evaluate_finding(finding.finding_id)
            generate_finding_evidence(finding.finding_id)
        if len(saved) > len(evidence_targets):
            collected.warnings.append(
                f"Evidence generation was limited to the top {len(evidence_targets)} finding(s) by risk score."
            )

    save_executive_summary()
    return SecuritySyncSummary(
        findings_ingested=len(saved),
        source_counts=collected.source_counts,
        warnings=collected.warnings,
        replaced_existing=replace_existing,
        preserved_categories=preserved_categories,
        mode=collected.mode,
    )


def run_demo() -> DemoSummary:
    reset_state(clear_reports=True)
    findings = ingest_demo()
    models = discover_and_register_models(source="local")
    replay_governance_trace()

    for finding in findings:
        analyze_finding(finding.finding_id)
        evaluate_finding(finding.finding_id)
        generate_finding_evidence(finding.finding_id)

    for model in models:
        analyze_model(model.model_inventory_id)
        evaluate_model(model.model_inventory_id)
        generate_model_evidence(model.model_inventory_id)

    save_executive_summary()
    return build_demo_summary()


def _process_findings(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    processed: List[NormalizedFinding] = []
    for finding in findings:
        risk = score_finding(finding)
        finding.risk_score = risk.risk_score
        finding.risk_rating = risk.risk_rating
        finding.risk_reasoning = risk.risk_reasoning
        finding.business_impact = risk.business_impact
        finding.mapped_controls = map_finding_to_controls(finding)
        processed.append(finding)
    return processed
