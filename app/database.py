from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Iterable, List

from app.config import get_settings
from app.models import (
    AppState,
    EvidenceMetadata,
    GovernanceDecision,
    ModelInventoryRecord,
    NormalizedFinding,
    utcnow_iso,
)


class JsonDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_state(AppState())

    def _read_state(self) -> AppState:
        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return AppState.model_validate(payload)

    def _write_state(self, state: AppState) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(state.model_dump(mode="json"), handle, indent=2)
        tmp_path.replace(self.path)

    def reset(self) -> AppState:
        with self._lock:
            state = AppState(last_reset=utcnow_iso())
            self._write_state(state)
            return state

    def get_state(self) -> AppState:
        with self._lock:
            return self._read_state()

    def save_findings(self, findings: Iterable[NormalizedFinding]) -> List[NormalizedFinding]:
        with self._lock:
            state = self._read_state()
            saved: List[NormalizedFinding] = []
            for finding in findings:
                finding.last_updated = utcnow_iso()
                state.findings[finding.finding_id] = finding
                saved.append(finding)
            self._write_state(state)
            return saved

    def replace_findings(
        self,
        findings: Iterable[NormalizedFinding],
        preserve_categories: Iterable[str] | None = None,
    ) -> List[NormalizedFinding]:
        with self._lock:
            state = self._read_state()
            preserve = {category.lower() for category in (preserve_categories or [])}
            preserved_findings = {
                finding_id: finding
                for finding_id, finding in state.findings.items()
                if finding.category.lower() in preserve
            }
            replaced_ids = {finding_id for finding_id in state.findings if finding_id not in preserved_findings}
            saved: List[NormalizedFinding] = []
            refreshed: dict[str, NormalizedFinding] = {}
            for finding in findings:
                finding.last_updated = utcnow_iso()
                refreshed[finding.finding_id] = finding
                saved.append(finding)
            preserved_findings.update(refreshed)
            state.findings = preserved_findings
            state.reports = [
                report
                for report in state.reports
                if not (report.target_type == "finding" and report.target_id in replaced_ids)
            ]
            self._write_state(state)
            return saved

    def save_finding(self, finding: NormalizedFinding) -> NormalizedFinding:
        self.save_findings([finding])
        return finding

    def get_findings(self) -> List[NormalizedFinding]:
        return list(self.get_state().findings.values())

    def get_finding(self, finding_id: str) -> NormalizedFinding | None:
        return self.get_state().findings.get(finding_id)

    def save_models(self, models: Iterable[ModelInventoryRecord]) -> List[ModelInventoryRecord]:
        with self._lock:
            state = self._read_state()
            saved: List[ModelInventoryRecord] = []
            for model in models:
                state.models[model.model_inventory_id] = model
                saved.append(model)
            self._write_state(state)
            return saved

    def replace_models(self, models: Iterable[ModelInventoryRecord]) -> List[ModelInventoryRecord]:
        with self._lock:
            state = self._read_state()
            saved = list(models)
            state.models = {model.model_inventory_id: model for model in saved}
            state.reports = [report for report in state.reports if report.target_type != "model"]
            self._write_state(state)
            return saved

    def save_model(self, model: ModelInventoryRecord) -> ModelInventoryRecord:
        self.save_models([model])
        return model

    def get_models(self) -> List[ModelInventoryRecord]:
        return list(self.get_state().models.values())

    def get_model(self, model_id: str) -> ModelInventoryRecord | None:
        return self.get_state().models.get(model_id)

    def save_governance_decision(self, decision: GovernanceDecision) -> GovernanceDecision:
        with self._lock:
            state = self._read_state()
            state.governance_decisions.append(decision)
            self._write_state(state)
            return decision

    def get_governance_decisions(self) -> List[GovernanceDecision]:
        return list(self.get_state().governance_decisions)

    def save_report(self, report: EvidenceMetadata) -> EvidenceMetadata:
        with self._lock:
            state = self._read_state()
            state.reports.append(report)
            self._write_state(state)
            return report

    def get_reports(self) -> List[EvidenceMetadata]:
        return list(self.get_state().reports)


_db_instance: JsonDatabase | None = None
_db_path: Path | None = None


def get_db() -> JsonDatabase:
    global _db_instance, _db_path
    settings = get_settings()
    if _db_instance is None or _db_path != settings.data_store_path:
        _db_instance = JsonDatabase(settings.data_store_path)
        _db_path = settings.data_store_path
    return _db_instance
