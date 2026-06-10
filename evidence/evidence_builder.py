from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ai.risk_analyzer import analyze_finding, analyze_model
from app.config import get_settings
from app.database import get_db
from app.models import EvidenceMetadata, ModelInventoryRecord, NormalizedFinding
from evals.local_evaluators import evaluate_finding_analysis, evaluate_model_analysis
from evidence.hash_chain import sha256_for_payload
from evidence.report_generator import render_finding_markdown, render_model_markdown


def build_finding_evidence(finding: NormalizedFinding) -> EvidenceMetadata:
    db = get_db()
    if finding.ai_analysis is None:
        finding.ai_analysis = analyze_finding(finding)
    if not finding.evaluations:
        finding.evaluations = evaluate_finding_analysis(finding)
    finding.trusted_analysis = all(result.pass_fail for result in finding.evaluations)

    governance_decisions = [
        decision
        for decision in db.get_governance_decisions()
        if decision.action in {"delete_resource", "apply_remediation", "read_resource"}
    ]

    payload = {
        "finding": finding.model_dump(mode="json"),
        "analysis": finding.ai_analysis.model_dump(mode="json"),
        "evaluations": [evaluation.model_dump(mode="json") for evaluation in finding.evaluations],
        "governance_decisions": [decision.model_dump(mode="json") for decision in governance_decisions],
    }
    sha256 = sha256_for_payload(payload)
    metadata = _write_evidence_files(
        prefix=f"evidence_{finding.finding_id}",
        payload=payload,
        markdown=render_finding_markdown(
            finding=finding,
            analysis=finding.ai_analysis,
            evaluations=finding.evaluations,
            governance_decisions=governance_decisions,
            evidence_id="pending",
            sha256=sha256,
        ),
        target_id=finding.finding_id,
        target_type="finding",
        summary=finding.title,
        sha256=sha256,
    )
    finding.evidence_id = metadata.evidence_id
    db.save_finding(finding)
    return metadata


def build_model_evidence(model: ModelInventoryRecord) -> EvidenceMetadata:
    db = get_db()
    if model.ai_analysis is None:
        model.ai_analysis = analyze_model(model)
    if not model.evaluations:
        model.evaluations = evaluate_model_analysis(model)
    model.trusted_analysis = all(result.pass_fail for result in model.evaluations)

    payload = {
        "model": model.model_dump(mode="json"),
        "analysis": model.ai_analysis.model_dump(mode="json"),
        "evaluations": [evaluation.model_dump(mode="json") for evaluation in model.evaluations],
    }
    sha256 = sha256_for_payload(payload)
    metadata = _write_evidence_files(
        prefix=f"model_evidence_{model.model_inventory_id}",
        payload=payload,
        markdown=render_model_markdown(
            model=model,
            analysis=model.ai_analysis,
            evaluations=model.evaluations,
            evidence_id="pending",
            sha256=sha256,
        ),
        target_id=model.model_inventory_id,
        target_type="model",
        summary=model.model_name,
        sha256=sha256,
    )
    model.evidence_id = metadata.evidence_id
    db.save_model(model)
    return metadata


def write_executive_summary_report(markdown: str) -> Path:
    settings = get_settings()
    path = settings.reports_dir / "executive_summary.md"
    path.write_text(markdown, encoding="utf-8")
    metadata = EvidenceMetadata(
        target_id="executive-summary",
        target_type="executive_summary",
        markdown_path=str(path),
        sha256=sha256_for_payload({"markdown": markdown}),
        summary="Executive summary",
    )
    get_db().save_report(metadata)
    return path


def _write_evidence_files(
    prefix: str,
    payload: Dict[str, Any],
    markdown: str,
    target_id: str,
    target_type: str,
    summary: str,
    sha256: str,
) -> EvidenceMetadata:
    settings = get_settings()
    json_path = settings.reports_dir / f"{prefix}.json"
    md_path = settings.reports_dir / f"{prefix}.md"

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")

    metadata = EvidenceMetadata(
        target_id=target_id,
        target_type=target_type,  # type: ignore[arg-type]
        json_path=str(json_path),
        markdown_path=str(md_path),
        sha256=sha256,
        summary=summary,
    )
    get_db().save_report(metadata)
    _update_markdown_metadata(md_path, metadata.evidence_id, sha256)
    return metadata


def _update_markdown_metadata(path: Path, evidence_id: str, sha256: str) -> None:
    content = path.read_text(encoding="utf-8")
    content = content.replace("Evidence ID: pending", f"Evidence ID: {evidence_id}")
    path.write_text(content.replace("Hash: " + sha256, f"Hash: {sha256}"), encoding="utf-8")
