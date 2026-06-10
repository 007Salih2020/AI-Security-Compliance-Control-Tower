from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.models import NormalizedFinding

LEVEL_MAP = {"warning": "Medium", "error": "High", "note": "Low"}


def parse_sarif_file(file_path: str | Path) -> List[NormalizedFinding]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    findings: List[NormalizedFinding] = []
    for run in payload.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "SARIF")
        for result in run.get("results", []):
            props = result.get("properties", {})
            findings.append(
                NormalizedFinding(
                    finding_id=result["ruleId"],
                    title=result.get("message", {}).get("text", result["ruleId"]),
                    description=result.get("message", {}).get("text", result["ruleId"]),
                    provider=props.get("provider", "Unknown"),
                    service=props.get("service", "Unknown"),
                    resource_id=props.get("resource_id", ""),
                    resource_name=props.get("resource_name", ""),
                    severity=LEVEL_MAP.get(result.get("level", "warning"), "Medium"),
                    status="open",
                    category=props.get("category", "Code Security"),
                    source_tool=tool_name,
                    compliance_frameworks=props.get("compliance_frameworks", []),
                    control_ids=props.get("control_ids", []),
                    remediation=props.get("remediation", "Investigate and remediate the code issue."),
                    evidence_references=[
                        result.get("locations", [{}])[0]
                        .get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri", "")
                    ],
                    created_at=props.get("created_at", ""),
                    asset_criticality=props.get("asset_criticality", "medium"),
                    internet_exposure=props.get("internet_exposure", False),
                    compliance_relevance=props.get("compliance_relevance", "medium"),
                    exploitability=props.get("exploitability", "medium"),
                    data_sensitivity=props.get("data_sensitivity", "internal"),
                )
            )
    return findings
