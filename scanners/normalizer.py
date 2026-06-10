from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.models import NormalizedFinding
from app.config import get_settings
from scanners.prowler_adapter import parse_prowler_file
from scanners.sarif_parser import parse_sarif_file
from scanners.sbom_parser import parse_sbom_file


def parse_risky_agent_trace(file_path: str | Path) -> List[NormalizedFinding]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    risky_action = next(
        (action for action in payload.get("actions", []) if action.get("action") == "delete_resource"),
        None,
    )
    if risky_action is None:
        return []

    finding = NormalizedFinding(
        finding_id="AI-AGENT-001",
        title="AI agent attempted destructive cloud action",
        description=(
            f"Agent {payload.get('agent_name')} attempted {risky_action['action']} against "
            f"{risky_action['target']} in {payload.get('environment')}."
        ),
        provider="Internal AI",
        service="AI Agent Runtime",
        resource_id=risky_action["target"],
        resource_name=payload.get("agent_name", "unknown-agent"),
        severity="Critical",
        status="open",
        category="AI Governance",
        source_tool="Agent Trace",
        compliance_frameworks=["ISO 27001", "NIST 800-53", "AI Governance"],
        control_ids=["A.5.1", "AI-AGENT-001", "AI-LOG-001"],
        remediation=(
            "Block destructive actions in policy, require human approval for remediation execution, "
            "and retain decision logs for review."
        ),
        evidence_references=[payload.get("trace_id", ""), risky_action.get("action_id", "")],
        created_at=risky_action["timestamp"],
        asset_criticality="critical",
        internet_exposure=False,
        compliance_relevance="high",
        exploitability="high",
        data_sensitivity="regulated",
        ai_agent_involved=True,
    )
    return [finding]


def load_findings_from_file(file_path: str | Path) -> List[NormalizedFinding]:
    path = Path(file_path)
    name = path.name.lower()
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if "prowler" in name or ".csv" in suffixes:
        return parse_prowler_file(file_path)
    if "sarif" in name or ".sarif" in suffixes:
        return parse_sarif_file(file_path)
    if "sbom" in name or "cyclonedx" in name or name.endswith("bom.json"):
        return parse_sbom_file(file_path)
    if "agent_trace" in name or "risky_ai_agent_trace" in name:
        return parse_risky_agent_trace(file_path)
    raise ValueError(f"Unsupported finding file type: {file_path}")


def load_demo_findings() -> List[NormalizedFinding]:
    settings = get_settings()
    files = [
        settings.samples_dir / "prowler_azure_findings.json",
        settings.samples_dir / "sarif_findings.json",
        settings.samples_dir / "sbom_findings.json",
        settings.samples_dir / "risky_ai_agent_trace.json",
    ]
    findings: List[NormalizedFinding] = []
    for file_path in files:
        findings.extend(load_findings_from_file(file_path))
    return findings
