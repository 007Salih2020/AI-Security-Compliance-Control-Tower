from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from app.models import NormalizedFinding, utcnow_iso

SEVERITY_MAP = {
    "informational": "Low",
    "info": "Low",
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "high": "High",
    "critical": "Critical",
    "warning": "Medium",
    "error": "High",
}

PASS_STATUSES = {"pass", "passed", "ok", "success", "compliant"}
FAIL_STATUSES = {"fail", "failed", "failure", "noncompliant", "open"}
SENSITIVE_DATA_MARKERS = {"key vault", "secret", "credential", "customer", "pii", "personal", "regulated"}
CONFIDENTIAL_MARKERS = {"confidential", "private endpoint", "sensitive", "vault", "database"}
INTERNET_MARKERS = {"public", "internet", "blob access", "public network", "external", "open to all"}
HIGH_CRITICALITY_SERVICES = {"keyvault", "storage", "compute", "network", "database", "microsoft.keyvault", "microsoft.storage"}


def parse_prowler_file(file_path: str | Path) -> List[NormalizedFinding]:
    path = Path(file_path)
    if path.suffix.lower() == ".csv":
        return _parse_prowler_csv(path)

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _parse_prowler_json_payload(payload)


def _parse_prowler_csv(path: Path) -> List[NormalizedFinding]:
    findings: List[NormalizedFinding] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            record = _lowercase_keys(row)
            if not _is_failing_status(record.get("status")):
                continue
            findings.append(_normalize_flat_prowler_record(record))
    return findings


def _parse_prowler_json_payload(payload: Any) -> List[NormalizedFinding]:
    if isinstance(payload, dict):
        for key in ("findings", "data", "results", "items", "value"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                return _parse_prowler_json_payload(candidate)
        raise ValueError("Unsupported Prowler JSON payload. Expected a list of findings or a wrapper object.")

    if not isinstance(payload, list):
        raise ValueError("Unsupported Prowler payload type.")
    if not payload:
        return []

    first = payload[0]
    if isinstance(first, dict) and _looks_like_normalized_finding(first):
        return [NormalizedFinding.model_validate(item) for item in payload]

    findings: List[NormalizedFinding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        normalized = _normalize_native_record(item)
        if normalized is not None:
            findings.append(normalized)
    return findings


def _normalize_native_record(record: Dict[str, Any]) -> NormalizedFinding | None:
    if _looks_like_ocsf_record(record):
        if not _is_failing_status(record.get("status")):
            return None
        return _normalize_ocsf_record(record)

    lowered = _lowercase_keys(record)
    if not _is_failing_status(lowered.get("status")):
        return None
    return _normalize_flat_prowler_record(lowered)


def _normalize_ocsf_record(record: Dict[str, Any]) -> NormalizedFinding:
    finding_info = record.get("finding_info") or record.get("finding") or {}
    resource = _first_resource(record.get("resources"))
    cloud = record.get("cloud") or {}
    metadata = record.get("metadata") or {}
    product = metadata.get("product") or {}
    remediation = record.get("remediation") or {}

    title = _first_text(
        finding_info.get("title"),
        record.get("title"),
        record.get("message"),
        "Prowler Azure finding",
    )
    description = _first_text(
        finding_info.get("desc"),
        finding_info.get("description"),
        record.get("message"),
        record.get("desc"),
        title,
    )
    resource_id = _first_text(
        resource.get("uid"),
        resource.get("resource_uid"),
        record.get("resource_uid"),
        record.get("resource_id"),
        "",
    )
    resource_name = _first_text(
        resource.get("name"),
        resource.get("resource", {}).get("name") if isinstance(resource.get("resource"), dict) else None,
        record.get("resource_name"),
        resource_id.rsplit("/", 1)[-1] if resource_id else None,
        "unknown-resource",
    )
    service = _first_text(
        resource.get("type"),
        record.get("service_name"),
        record.get("service"),
        "Azure Resource",
    )
    severity = _normalize_severity(record.get("severity"), finding_info.get("severity"), record.get("severity_id"))
    provider = _normalize_provider(
        _first_text(
            cloud.get("provider"),
            product.get("vendor_name"),
            record.get("provider"),
            "Azure",
        )
    )
    subscription_id = _first_text(
        cloud.get("account", {}).get("uid") if isinstance(cloud.get("account"), dict) else None,
        record.get("subscription_id"),
        "",
    )
    timestamp = _first_text(
        record.get("time"),
        record.get("created_time"),
        record.get("event_time"),
        record.get("activity_time"),
        utcnow_iso(),
    )
    remediation_text = _first_text(
        remediation.get("desc"),
        remediation.get("recommendation"),
        record.get("remediation"),
        "Investigate the failing Prowler check and remediate the underlying Azure misconfiguration.",
    )
    evidence_references = _deduplicate_strings(
        [
            resource_id,
            finding_info.get("uid"),
            record.get("uid"),
            remediation.get("url"),
            remediation.get("reference"),
        ]
        + _as_list(remediation.get("references"))
        + _as_list(record.get("related_urls"))
    )
    category = _infer_category(title, description, service)
    internet_exposure = _has_any_marker(title, description, resource_name, service, markers=INTERNET_MARKERS)
    data_sensitivity = _infer_data_sensitivity(title, description, resource_name)
    exploitability = "high" if internet_exposure else "medium"
    asset_criticality = _infer_asset_criticality(service, severity)
    finding_uid = _first_text(finding_info.get("uid"), record.get("uid"), title)
    finding_id = _stable_finding_id("PROWLER", finding_uid, resource_id, resource_name)

    return NormalizedFinding(
        finding_id=finding_id,
        title=title,
        description=description,
        provider=provider,
        service=service,
        resource_id=resource_id,
        resource_name=resource_name,
        severity=severity,
        status="open",
        category=category,
        source_tool="Prowler",
        compliance_frameworks=_extract_frameworks(record),
        control_ids=_extract_control_ids(record),
        remediation=remediation_text,
        evidence_references=evidence_references,
        created_at=timestamp,
        asset_criticality=asset_criticality,
        internet_exposure=internet_exposure,
        compliance_relevance="high",
        exploitability=exploitability,
        data_sensitivity=data_sensitivity,
    )


def _normalize_flat_prowler_record(record: Dict[str, Any]) -> NormalizedFinding:
    title = _first_text(
        record.get("check_title"),
        record.get("finding_info.title"),
        record.get("title"),
        record.get("description"),
        "Prowler Azure finding",
    )
    description = _first_text(
        record.get("status_extended"),
        record.get("extended_status"),
        record.get("description"),
        title,
    )
    resource_id = _first_text(
        record.get("resource_uid"),
        record.get("resource_id"),
        record.get("resource"),
        "",
    )
    resource_name = _first_text(
        record.get("resource_name"),
        resource_id.rsplit("/", 1)[-1] if resource_id else None,
        "unknown-resource",
    )
    service = _first_text(
        record.get("service_name"),
        record.get("service"),
        record.get("resource_type"),
        "Azure Resource",
    )
    severity = _normalize_severity(record.get("severity"), record.get("severity_label"), record.get("status_severity"))
    provider = _normalize_provider(_first_text(record.get("provider"), "Azure"))
    check_id = _first_text(record.get("check_id"), record.get("checkid"), title)
    remediation_text = _first_text(
        record.get("remediation_recommendation_text"),
        record.get("remediation"),
        "Investigate the failing Prowler check and remediate the underlying Azure misconfiguration.",
    )
    timestamp = _first_text(
        record.get("timestamp"),
        record.get("created_at"),
        record.get("assessment_start_time"),
        utcnow_iso(),
    )
    evidence_references = _deduplicate_strings(
        [
            resource_id,
            record.get("related_url"),
            record.get("documentation_url"),
            check_id,
        ]
    )
    category = _infer_category(title, description, service)
    internet_exposure = _coerce_bool(record.get("internet_exposure")) or _has_any_marker(
        title, description, resource_name, service, markers=INTERNET_MARKERS
    )
    data_sensitivity = _infer_data_sensitivity(title, description, resource_name)
    exploitability = "high" if internet_exposure else "medium"
    asset_criticality = _infer_asset_criticality(service, severity)
    compliance_frameworks = _extract_frameworks(record)
    control_ids = _extract_control_ids(record)
    finding_id = _stable_finding_id("PROWLER", check_id, resource_id, resource_name)

    return NormalizedFinding(
        finding_id=finding_id,
        title=title,
        description=description,
        provider=provider,
        service=service,
        resource_id=resource_id,
        resource_name=resource_name,
        severity=severity,
        status="open",
        category=category,
        source_tool="Prowler",
        compliance_frameworks=compliance_frameworks,
        control_ids=control_ids,
        remediation=remediation_text,
        evidence_references=evidence_references,
        created_at=timestamp,
        asset_criticality=asset_criticality,
        internet_exposure=internet_exposure,
        compliance_relevance="high",
        exploitability=exploitability,
        data_sensitivity=data_sensitivity,
    )


def _looks_like_normalized_finding(record: Dict[str, Any]) -> bool:
    return {"finding_id", "title", "description", "provider", "service"}.issubset(record)


def _looks_like_ocsf_record(record: Dict[str, Any]) -> bool:
    return "finding_info" in record or "resources" in record or "cloud" in record


def _first_resource(resources: Any) -> Dict[str, Any]:
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            return first
    return {}


def _normalize_provider(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "azure":
        return "Azure"
    if normalized == "microsoft":
        return "Azure"
    return value.strip() or "Azure"


def _normalize_severity(*values: Any) -> str:
    for value in values:
        if isinstance(value, dict):
            label = value.get("label") or value.get("name")
            if label:
                return _normalize_severity(label)
            numeric = value.get("id") or value.get("value")
            if numeric is not None:
                return _normalize_severity(numeric)
        if isinstance(value, (int, float)):
            if value >= 4:
                return "Critical"
            if value >= 3:
                return "High"
            if value >= 2:
                return "Medium"
            return "Low"
        if isinstance(value, str):
            label = SEVERITY_MAP.get(value.strip().lower())
            if label:
                return label
    return "Medium"


def _is_failing_status(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        value = value.get("label") or value.get("name") or value.get("status")
    normalized = str(value).strip().lower()
    if not normalized:
        return True
    if normalized in FAIL_STATUSES:
        return True
    if normalized in PASS_STATUSES:
        return False
    return "fail" in normalized or "noncompliant" in normalized or "open" in normalized


def _extract_frameworks(record: Dict[str, Any]) -> List[str]:
    frameworks: List[str] = []
    for candidate in (
        record.get("compliance_frameworks"),
        record.get("frameworks"),
        record.get("compliance"),
        record.get("compliances"),
    ):
        if isinstance(candidate, dict):
            frameworks.extend(str(key) for key, value in candidate.items() if value)
        elif isinstance(candidate, list):
            frameworks.extend(str(item) for item in candidate if item)
        elif isinstance(candidate, str) and candidate:
            frameworks.extend(part.strip() for part in candidate.split(",") if part.strip())
    return _deduplicate_strings(frameworks)


def _extract_control_ids(record: Dict[str, Any]) -> List[str]:
    control_ids: List[str] = []
    for candidate in (
        record.get("control_ids"),
        record.get("compliance_controls"),
        record.get("compliance"),
        record.get("compliances"),
    ):
        if isinstance(candidate, dict):
            for value in candidate.values():
                control_ids.extend(_flatten_strings(value))
        else:
            control_ids.extend(_flatten_strings(candidate))
    return _deduplicate_strings(control_ids)


def _flatten_strings(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        flattened: List[str] = []
        for item in value:
            flattened.extend(_flatten_strings(item))
        return flattened
    if isinstance(value, dict):
        flattened: List[str] = []
        for item in value.values():
            flattened.extend(_flatten_strings(item))
        return flattened
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    return [str(value)]


def _infer_category(title: str, description: str, service: str) -> str:
    text = " ".join([title, description, service]).lower()
    if "policy" in text or "compliance" in text:
        return "Cloud Compliance"
    if "log" in text or "monitor" in text or "diagnostic" in text:
        return "Logging and Monitoring"
    if "network" in text or "public" in text or "firewall" in text:
        return "Network Security"
    if "identity" in text or "role" in text or "permission" in text:
        return "Identity and Access"
    return "Cloud Security Posture"


def _infer_data_sensitivity(title: str, description: str, resource_name: str) -> str:
    text = " ".join([title, description, resource_name]).lower()
    if any(marker in text for marker in SENSITIVE_DATA_MARKERS):
        return "regulated"
    if any(marker in text for marker in CONFIDENTIAL_MARKERS):
        return "confidential"
    return "internal"


def _infer_asset_criticality(service: str, severity: str) -> str:
    if severity == "Critical":
        return "critical"
    normalized_service = service.lower()
    if any(marker in normalized_service for marker in HIGH_CRITICALITY_SERVICES):
        return "high"
    if severity == "High":
        return "high"
    return "medium"


def _has_any_marker(*values: str, markers: Iterable[str]) -> bool:
    haystack = " ".join(values).lower()
    return any(marker in haystack for marker in markers)


def _deduplicate_strings(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    deduped: List[str] = []
    for value in values:
        if value in (None, ""):
            continue
        if isinstance(value, list):
            for item in value:
                for flattened in _deduplicate_strings([item]):
                    if flattened not in seen:
                        seen.add(flattened)
                        deduped.append(flattened)
            continue
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _stable_finding_id(prefix: str, *parts: str) -> str:
    value = ":".join(part for part in parts if part)
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _lowercase_keys(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in payload.items():
        normalized[str(key).strip().lower()] = value
    return normalized


def _first_text(*values: Any) -> str:
    for value in values:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(value)]
