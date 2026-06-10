from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

import yaml

from app.models import ComplianceControl, ModelInventoryRecord, NormalizedFinding

COMPLIANCE_DIR = Path(__file__).resolve().parent
CONTROL_FILES = [
    "iso27001.yaml",
    "nist80053.yaml",
    "dora.yaml",
    "cis.yaml",
    "soc2.yaml",
    "ai_model_governance.yaml",
]


@lru_cache(maxsize=1)
def load_all_controls() -> List[ComplianceControl]:
    controls: List[ComplianceControl] = []
    for filename in CONTROL_FILES:
        file_path = COMPLIANCE_DIR / filename
        with file_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        framework = payload.get("framework", filename)
        for item in payload.get("controls", []):
            item["framework"] = framework
            controls.append(ComplianceControl.model_validate(item))
    return controls


def _find_keywords(texts: Iterable[str], keywords: Iterable[str]) -> bool:
    haystack = " ".join(texts).lower()
    return any(keyword.lower() in haystack for keyword in keywords)


def map_finding_to_controls(finding: NormalizedFinding) -> List[ComplianceControl]:
    controls: List[ComplianceControl] = []
    texts = [finding.title, finding.description, finding.category, finding.service]
    for control in load_all_controls():
        if finding.finding_id in control.finding_ids:
            controls.append(control)
            continue
        if finding.category in control.finding_categories:
            controls.append(control)
            continue
        if control.control_id in finding.control_ids:
            controls.append(control)
            continue
        if _find_keywords(texts, control.keywords):
            controls.append(control)
    return _deduplicate_controls(controls)


def map_model_to_controls(model: ModelInventoryRecord) -> List[ComplianceControl]:
    controls: List[ComplianceControl] = []
    texts = [
        model.model_name,
        model.application_name,
        model.use_case,
        model.data_classification,
        model.approval_status,
        model.owner,
    ]
    active_triggers = set(_model_triggers(model))
    for control in load_all_controls():
        if active_triggers.intersection(control.model_triggers):
            controls.append(control)
            continue
        if _find_keywords(texts, control.keywords):
            controls.append(control)
    return _deduplicate_controls(controls)


def _model_triggers(model: ModelInventoryRecord) -> List[str]:
    triggers: List[str] = []
    if model.owner.lower() == "unknown":
        triggers.append("missing_owner")
    if model.use_case.lower() == "unknown":
        triggers.append("unknown_use_case")
    if model.environment.lower() == "production":
        triggers.append("production")
    if model.internet_accessible or model.public_endpoint:
        triggers.append("internet_accessible")
    if not model.logging_enabled:
        triggers.append("missing_logging")
    if not model.content_filtering_enabled:
        triggers.append("no_content_filter")
    if not model.evaluation_available:
        triggers.append("missing_evaluation")
    if not model.red_team_tested:
        triggers.append("missing_red_team")
    if model.used_by_agent:
        triggers.append("used_by_agent")
    if model.approval_status != "approved":
        triggers.append("needs_review")
    if model.processes_personal_data or model.processes_confidential_data:
        triggers.append("sensitive_data")
    return triggers


def _deduplicate_controls(controls: List[ComplianceControl]) -> List[ComplianceControl]:
    seen: set[str] = set()
    deduped: List[ComplianceControl] = []
    for control in controls:
        key = f"{control.framework}:{control.control_id}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(control)
    return deduped
