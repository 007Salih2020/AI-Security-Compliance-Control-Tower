from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.models import NormalizedFinding


def parse_sbom_file(file_path: str | Path) -> List[NormalizedFinding]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if payload.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx_sbom(payload)

    findings: List[NormalizedFinding] = []
    created_at = payload.get("generated_at", "")
    for dependency in payload.get("dependencies", []):
        findings.append(
            NormalizedFinding(
                finding_id=dependency["vulnerability_id"],
                title=dependency["title"],
                description=dependency["description"],
                provider=dependency.get("provider", "SBOM"),
                service=dependency.get("service", "Dependency"),
                resource_id=dependency["resource_id"],
                resource_name=dependency["resource_name"],
                severity=dependency["severity"],
                status="open",
                category=dependency["category"],
                source_tool="CycloneDX",
                compliance_frameworks=dependency.get("compliance_frameworks", []),
                control_ids=dependency.get("control_ids", []),
                remediation=dependency["remediation"],
                evidence_references=[dependency["component"]],
                created_at=created_at,
                asset_criticality=dependency.get("asset_criticality", "medium"),
                internet_exposure=dependency.get("internet_exposure", False),
                compliance_relevance=dependency.get("compliance_relevance", "medium"),
                exploitability=dependency.get("exploitability", "medium"),
                data_sensitivity=dependency.get("data_sensitivity", "internal"),
            )
        )
    return findings


def _parse_cyclonedx_sbom(payload: dict) -> List[NormalizedFinding]:
    metadata = payload.get("metadata", {})
    created_at = metadata.get("timestamp", "")
    components = payload.get("components", [])
    component_index: dict[str, dict] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        for key in ("bom-ref", "ref", "purl", "name"):
            value = component.get(key)
            if value:
                component_index[str(value)] = component

    findings: List[NormalizedFinding] = []
    for vulnerability in payload.get("vulnerabilities", []):
        if not isinstance(vulnerability, dict):
            continue
        affected = vulnerability.get("affects", []) or [{}]
        for reference in affected:
            ref = reference.get("ref", "") if isinstance(reference, dict) else str(reference)
            component = component_index.get(ref, {})
            severity = _cyclonedx_severity(vulnerability)
            findings.append(
                NormalizedFinding(
                    finding_id=str(vulnerability.get("id") or ref or component.get("name") or "SBOM-VULN"),
                    title=str(vulnerability.get("id") or component.get("name") or "Dependency vulnerability"),
                    description=str(
                        vulnerability.get("description")
                        or vulnerability.get("detail")
                        or f"Dependency {component.get('name', ref or 'unknown-component')} has a reported vulnerability."
                    ),
                    provider="SBOM",
                    service="Dependency",
                    resource_id=str(ref or vulnerability.get("id") or component.get("name") or ""),
                    resource_name=str(component.get("name") or ref or "unknown-component"),
                    severity=severity,
                    status="open",
                    category="Dependency Vulnerability",
                    source_tool="CycloneDX",
                    compliance_frameworks=[],
                    control_ids=[],
                    remediation=_cyclonedx_remediation(vulnerability),
                    evidence_references=_cyclonedx_evidence_refs(component, vulnerability, ref),
                    created_at=created_at,
                    asset_criticality="medium",
                    internet_exposure=False,
                    compliance_relevance="medium",
                    exploitability="medium",
                    data_sensitivity="internal",
                )
            )
    return findings


def _cyclonedx_severity(vulnerability: dict) -> str:
    for rating in vulnerability.get("ratings", []):
        severity = str(rating.get("severity", "")).strip().lower()
        if severity == "critical":
            return "Critical"
        if severity == "high":
            return "High"
        if severity in {"medium", "moderate"}:
            return "Medium"
        if severity in {"low", "info", "informational"}:
            return "Low"
    fallback = str(vulnerability.get("severity", "medium")).strip().lower()
    if fallback == "critical":
        return "Critical"
    if fallback == "high":
        return "High"
    if fallback in {"medium", "moderate"}:
        return "Medium"
    return "Low"


def _cyclonedx_remediation(vulnerability: dict) -> str:
    analysis = vulnerability.get("analysis", {})
    response = analysis.get("response")
    if isinstance(response, list) and response:
        return f"Recommended response: {', '.join(str(item) for item in response)}."
    recommendation = vulnerability.get("recommendation")
    if recommendation:
        return str(recommendation)
    return "Upgrade or replace the vulnerable dependency and regenerate the SBOM."


def _cyclonedx_evidence_refs(component: dict, vulnerability: dict, ref: str) -> List[str]:
    refs: List[str] = []
    for value in (
        component.get("purl"),
        component.get("bom-ref"),
        component.get("name"),
        vulnerability.get("id"),
        vulnerability.get("source", {}).get("url") if isinstance(vulnerability.get("source"), dict) else None,
        ref,
    ):
        if value:
            refs.append(str(value))
    return refs
