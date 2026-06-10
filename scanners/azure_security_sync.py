from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import requests
from azure.core.credentials import TokenCredential
from azure.identity import AzureCliCredential, DefaultAzureCredential, EnvironmentCredential, ManagedIdentityCredential

from app.config import get_settings
from app.models import NormalizedFinding, utcnow_iso
from scanners.github_artifacts import ingest_github_artifacts
from scanners.prowler_adapter import parse_prowler_file

MANAGEMENT_SCOPE = "https://management.azure.com/.default"
POLICY_STATES_API_VERSION = "2024-10-01"
ACTIVITY_LOG_API_VERSION = "2015-04-01"

PUBLIC_MARKERS = {"public", "internet", "blob", "firewall", "network", "external"}
LOGGING_MARKERS = {"diagnostic", "logging", "log analytics", "monitor"}
SENSITIVE_MARKERS = {"key vault", "secret", "credential", "identity", "sql", "database", "storage"}
HIGH_RISK_OPERATION_MARKERS = {
    "delete",
    "roleassignments/write",
    "roleassignments/delete",
    "diagnosticsettings/write",
    "diagnosticsettings/delete",
    "listkeys/action",
    "regeneratekey/action",
    "firewallrules/write",
}


@dataclass(slots=True)
class AzureSecuritySyncResult:
    findings: List[NormalizedFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    source_counts: Dict[str, int] = field(default_factory=dict)
    mode: str = "disabled"


class AzureSecuritySyncError(RuntimeError):
    """Raised when live Azure security sync cannot be completed."""


class AzureArmSyncRequestError(AzureSecuritySyncError):
    def __init__(self, method: str, url: str, status_code: int, response_text: str) -> None:
        self.method = method
        self.url = url
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(f"Azure ARM {method} failed for {url}: {status_code} {response_text}")


class AzureSecuritySyncAdapter:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.credential: TokenCredential | None = None
        self.credential_label = "uninitialized"
        self._session = requests.Session()
        self._arm_token: str | None = None

    def collect(
        self,
        lookback_hours: int | None = None,
        include_policy_states: bool = True,
        include_activity_log: bool = True,
        include_prowler: bool = True,
        include_github_artifacts: bool = True,
    ) -> AzureSecuritySyncResult:
        warnings: List[str] = []
        result = AzureSecuritySyncResult(mode="local-only")

        if include_policy_states or include_activity_log:
            subscriptions = self._resolve_subscription_ids()
            errors: List[str] = []
            best_result: AzureSecuritySyncResult | None = None

            for credential_label, credential in self._credential_candidates():
                self.credential = credential
                self.credential_label = credential_label
                self._arm_token = None

                try:
                    candidate = self._collect_with_current_credential(
                        subscriptions=subscriptions,
                        lookback_hours=lookback_hours or self.settings.azure_activity_log_lookback_hours,
                        include_policy_states=include_policy_states,
                        include_activity_log=include_activity_log,
                    )
                    if self.settings.azure_auth_mode != "auto":
                        result = candidate
                        break
                    if best_result is None or len(candidate.findings) > len(best_result.findings):
                        best_result = candidate
                    if credential_label == "azure_cli":
                        result = best_result or candidate
                        break
                except AzureSecuritySyncError as exc:
                    errors.append(f"{credential_label}: {exc}")
                    if self.settings.azure_auth_mode != "auto" or not self._is_retryable_credential_error(exc):
                        raise

            if result.findings == [] and best_result is not None:
                result = best_result
            if best_result is None and not result.findings and errors:
                warnings.extend(errors)

        if include_prowler:
            prowler_result = self._collect_prowler_findings()
            result.findings.extend(prowler_result.findings)
            result.warnings.extend(prowler_result.warnings)
            result.source_counts.update(_merge_counts(result.source_counts, prowler_result.source_counts))

        if include_github_artifacts:
            github_result = ingest_github_artifacts()
            if github_result.findings:
                result.findings.extend(github_result.findings)
                result.source_counts["GitHub Artifacts"] = len(github_result.findings)
            result.warnings.extend(github_result.warnings)

        result.warnings.extend(warnings)
        result.findings = _deduplicate_findings(result.findings)
        if not result.source_counts:
            result.source_counts = _count_findings_by_source(result.findings)
        if result.findings and result.mode == "local-only":
            result.mode = "local-artifacts"
        return result

    def _collect_with_current_credential(
        self,
        subscriptions: Sequence[str],
        lookback_hours: int,
        include_policy_states: bool,
        include_activity_log: bool,
    ) -> AzureSecuritySyncResult:
        self._arm_token = self._get_management_token()
        findings: List[NormalizedFinding] = []
        source_counts: Dict[str, int] = {}

        if include_policy_states:
            policy_findings = self._collect_policy_state_findings(subscriptions)
            findings.extend(policy_findings)
            source_counts["Azure Policy"] = len(policy_findings)

        if include_activity_log:
            activity_findings = self._collect_activity_log_findings(subscriptions, lookback_hours=lookback_hours)
            findings.extend(activity_findings)
            source_counts["Azure Activity Log"] = len(activity_findings)

        return AzureSecuritySyncResult(
            findings=findings,
            warnings=[],
            source_counts=source_counts,
            mode=f"live:{self.credential_label}",
        )

    def _credential_candidates(self) -> List[tuple[str, TokenCredential]]:
        mode = self.settings.azure_auth_mode or "auto"
        if mode == "env":
            return [("environment", EnvironmentCredential())]
        if mode == "cli":
            return [("azure_cli", AzureCliCredential())]
        if mode in {"managed_identity", "msi"}:
            return [("managed_identity", ManagedIdentityCredential())]
        if mode == "default":
            return [("default", DefaultAzureCredential(exclude_interactive_browser_credential=True))]

        candidates: List[tuple[str, TokenCredential]] = []
        if self._has_environment_credential():
            candidates.append(("environment", EnvironmentCredential()))
        candidates.append(("azure_cli", AzureCliCredential()))
        candidates.append(("managed_identity", ManagedIdentityCredential()))
        return candidates

    def _has_environment_credential(self) -> bool:
        return bool(
            self.settings.azure_tenant_id
            and self.settings.azure_client_id
            and self.settings.azure_client_secret
        )

    def _resolve_subscription_ids(self) -> List[str]:
        configured = [item.strip() for item in self.settings.azure_subscription_id.split(",") if item.strip()]
        if configured:
            return configured

        cli_ids = self._subscription_ids_from_cli()
        if cli_ids:
            return cli_ids
        raise AzureSecuritySyncError(
            "No Azure subscription scope was found. Set AZURE_SUBSCRIPTION_ID or run az login and az account set."
        )

    def _subscription_ids_from_cli(self) -> List[str]:
        try:
            result = subprocess.run(
                ["az", "account", "show", "--output", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        subscription_id = str(payload.get("id", "")).strip()
        return [subscription_id] if subscription_id else []

    def _get_management_token(self) -> str:
        if self.credential is None:
            raise AzureSecuritySyncError("Azure credential is not initialized.")
        try:
            return self.credential.get_token(MANAGEMENT_SCOPE).token
        except Exception as exc:  # pragma: no cover - external auth
            raise AzureSecuritySyncError(
                f"Azure authentication failed for credential mode {self.credential_label}. "
                "Verify Azure service principal settings or run az login."
            ) from exc

    def _headers(self) -> Dict[str, str]:
        if not self._arm_token:
            raise AzureSecuritySyncError("Azure access token is not initialized.")
        return {"Authorization": f"Bearer {self._arm_token}", "Content-Type": "application/json"}

    def _arm_get(self, path_or_url: str, api_version: str, extra_params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("https://") else f"https://management.azure.com{path_or_url}"
        params = {"api-version": api_version}
        if extra_params:
            params.update(extra_params)
        response = self._session.get(url, headers=self._headers(), params=params, timeout=60)
        if response.status_code == 404:
            return {}
        if response.status_code >= 400:
            raise AzureArmSyncRequestError("GET", url, response.status_code, response.text)
        return response.json()

    def _arm_post(
        self,
        path_or_url: str,
        api_version: str,
        payload: Dict[str, Any] | None = None,
        extra_params: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("https://") else f"https://management.azure.com{path_or_url}"
        params = {"api-version": api_version}
        if extra_params:
            params.update(extra_params)
        response = self._session.post(url, headers=self._headers(), params=params, json=payload or {}, timeout=60)
        if response.status_code >= 400:
            raise AzureArmSyncRequestError("POST", url, response.status_code, response.text)
        return response.json()

    def _collect_policy_state_findings(self, subscriptions: Sequence[str]) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        for subscription_id in subscriptions:
            response = self._arm_post(
                f"/subscriptions/{subscription_id}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults",
                api_version=POLICY_STATES_API_VERSION,
                payload={},
                extra_params={
                    "$top": str(self.settings.azure_policy_query_limit),
                    "$filter": "ComplianceState eq 'NonCompliant'",
                    "$orderby": "Timestamp desc",
                },
            )
            for item in response.get("value", []):
                if not isinstance(item, dict):
                    continue
                findings.append(_normalize_policy_state(item))
        return findings

    def _collect_activity_log_findings(self, subscriptions: Sequence[str], lookback_hours: int) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=lookback_hours)
        filter_value = (
            f"eventTimestamp ge '{start.replace(microsecond=0).isoformat().replace('+00:00', 'Z')}' and "
            f"eventTimestamp le '{end.replace(microsecond=0).isoformat().replace('+00:00', 'Z')}'"
        )
        for subscription_id in subscriptions:
            next_url = (
                f"https://management.azure.com/subscriptions/{subscription_id}/providers/"
                "Microsoft.Insights/eventtypes/management/values"
            )
            pages = 0
            while next_url and pages < 5:
                response = self._arm_get(
                    next_url,
                    api_version=ACTIVITY_LOG_API_VERSION,
                    extra_params={"$filter": filter_value},
                )
                for event in response.get("value", []):
                    if not isinstance(event, dict) or not _is_risky_activity_event(event):
                        continue
                    findings.append(_normalize_activity_log_event(event))
                next_url = response.get("nextLink")
                pages += 1
        return findings

    def _collect_prowler_findings(self) -> AzureSecuritySyncResult:
        result = AzureSecuritySyncResult(mode="local-prowler")
        if self.settings.enable_local_prowler_execution:
            warning = self._maybe_execute_local_prowler()
            if warning:
                result.warnings.append(warning)

        candidate_files = _find_prowler_output_candidates(
            self.settings.prowler_output_dir,
            filename_prefix=self.settings.prowler_output_filename_prefix,
        )
        for candidate in candidate_files:
            try:
                findings = parse_prowler_file(candidate)
            except Exception as exc:  # pragma: no cover - depends on external file contents
                result.warnings.append(f"Failed to parse Prowler output {candidate.name}: {exc}")
                continue
            if findings:
                result.findings.extend(findings)
                result.source_counts["Prowler"] = len(findings)
                return result

        result.warnings.append("Prowler findings were not loaded because no native Prowler output file was found.")
        return result

    def _maybe_execute_local_prowler(self) -> str | None:
        prowler_binary = shutil.which(self.settings.prowler_binary)
        if not prowler_binary:
            return "ENABLE_LOCAL_PROWLER_EXECUTION=true is set, but the prowler binary is not available on PATH."

        auth_flag = _prowler_auth_flag(self.credential_label, self.settings.azure_auth_mode)
        command = [
            prowler_binary,
            "azure",
            auth_flag,
            "--output-formats",
            "json-ocsf",
            "csv",
            "--output-directory",
            str(self.settings.prowler_output_dir),
            "--output-filename",
            self.settings.prowler_output_filename_prefix,
        ]
        subscriptions = [item.strip() for item in self.settings.azure_subscription_id.split(",") if item.strip()]
        if subscriptions:
            command.extend(["--subscription-ids", *subscriptions])
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:  # pragma: no cover - depends on local prowler install
            stderr = exc.stderr.strip() or exc.stdout.strip()
            return f"Local Prowler execution failed: {stderr or exc}"
        return None

    def _is_retryable_credential_error(self, exc: AzureSecuritySyncError) -> bool:
        if isinstance(exc, AzureArmSyncRequestError):
            return exc.status_code in {401, 403}
        message = str(exc).lower()
        retryable_markers = ("authentication", "authorization", "access is denied", "permission", "forbidden", "401", "403")
        return any(marker in message for marker in retryable_markers)


def collect_live_security_findings(
    lookback_hours: int | None = None,
    include_policy_states: bool = True,
    include_activity_log: bool = True,
    include_prowler: bool = True,
    include_github_artifacts: bool = True,
) -> AzureSecuritySyncResult:
    return AzureSecuritySyncAdapter().collect(
        lookback_hours=lookback_hours,
        include_policy_states=include_policy_states,
        include_activity_log=include_activity_log,
        include_prowler=include_prowler,
        include_github_artifacts=include_github_artifacts,
    )


def _normalize_policy_state(record: Dict[str, Any]) -> NormalizedFinding:
    policy_name = str(record.get("policyDefinitionName") or record.get("policyDefinitionAction") or "policy")
    assignment_name = str(record.get("policyAssignmentName") or "policy-assignment")
    resource_id = str(record.get("resourceId") or "")
    resource_name = resource_id.rsplit("/", 1)[-1] if resource_id else "unknown-resource"
    resource_type = str(record.get("resourceType") or "Azure Resource")
    timestamp = str(record.get("timestamp") or utcnow_iso())
    title = f"Azure Policy non-compliance: {policy_name}"
    description = (
        f"Resource {resource_name} is non-compliant with policy {policy_name} under assignment {assignment_name}. "
        f"Compliance state: {record.get('complianceState', 'NonCompliant')}."
    )
    severity = _severity_from_text(title, description, default="High")
    internet_exposure = _text_has_markers(title, description, markers=PUBLIC_MARKERS)
    data_sensitivity = _data_sensitivity_from_text(title, description, resource_type)
    return NormalizedFinding(
        finding_id=_stable_finding_id(
            "AZPOL",
            str(record.get("policyAssignmentId") or ""),
            str(record.get("policyDefinitionId") or ""),
            resource_id,
        ),
        title=title,
        description=description,
        provider="Azure",
        service=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        severity=severity,
        status="open",
        category=_category_from_text(title, description),
        source_tool="Azure Policy",
        compliance_frameworks=["Azure Policy"],
        control_ids=[],
        remediation=(
            f"Review policy assignment {assignment_name}, correct the resource configuration, and re-run policy evaluation."
        ),
        evidence_references=[
            str(record.get("policyAssignmentId") or ""),
            str(record.get("policyDefinitionId") or ""),
        ],
        created_at=timestamp,
        asset_criticality=_asset_criticality_from_text(resource_type, severity),
        internet_exposure=internet_exposure,
        compliance_relevance="high",
        exploitability="high" if internet_exposure else "medium",
        data_sensitivity=data_sensitivity,
    )


def _normalize_activity_log_event(record: Dict[str, Any]) -> NormalizedFinding:
    operation_name = _nested_value(record, "operationName", "localizedValue") or _nested_value(
        record, "operationName", "value"
    )
    resource_id = str(record.get("resourceId") or "")
    resource_name = resource_id.rsplit("/", 1)[-1] if resource_id else "unknown-resource"
    provider = _nested_value(record, "resourceProviderName", "localizedValue") or _nested_value(
        record, "resourceProviderName", "value"
    )
    status = _nested_value(record, "status", "localizedValue") or _nested_value(record, "status", "value") or "Unknown"
    caller = str(record.get("caller") or "unknown-caller")
    timestamp = str(record.get("eventTimestamp") or utcnow_iso())
    title = f"Risky Azure control-plane activity: {operation_name or 'operation'}"
    description = (
        f"Caller {caller} triggered {operation_name or 'an Azure management operation'} on {resource_name}. "
        f"Operation status: {status}."
    )
    severity = _severity_from_activity(operation_name or "", resource_id, status)
    internet_exposure = _text_has_markers(title, description, resource_id, markers=PUBLIC_MARKERS)
    return NormalizedFinding(
        finding_id=_stable_finding_id(
            "AZACT",
            str(record.get("eventDataId") or ""),
            str(record.get("correlationId") or ""),
            resource_id,
        ),
        title=title,
        description=description,
        provider="Azure",
        service=str(provider or "Azure Activity Log"),
        resource_id=resource_id,
        resource_name=resource_name,
        severity=severity,
        status="open",
        category=_category_from_text(title, description),
        source_tool="Azure Activity Log",
        compliance_frameworks=["Azure Activity Log"],
        control_ids=[],
        remediation="Review the initiating identity, validate the change, and confirm logging or approval controls were followed.",
        evidence_references=[
            str(record.get("eventDataId") or ""),
            str(record.get("correlationId") or ""),
        ],
        created_at=timestamp,
        asset_criticality=_asset_criticality_from_text(resource_id, severity),
        internet_exposure=internet_exposure,
        compliance_relevance="high",
        exploitability="high" if severity in {"High", "Critical"} else "medium",
        data_sensitivity=_data_sensitivity_from_text(title, description, resource_id),
    )


def _is_risky_activity_event(record: Dict[str, Any]) -> bool:
    operation = (
        _nested_value(record, "operationName", "value")
        or _nested_value(record, "operationName", "localizedValue")
        or ""
    ).lower()
    category = (_nested_value(record, "category", "localizedValue") or "").lower()
    if category and category != "administrative":
        return False
    if any(marker in operation for marker in HIGH_RISK_OPERATION_MARKERS):
        return True
    if "delete" in operation:
        return True
    if "write" in operation and any(marker in operation for marker in ("storageaccounts", "vaults", "publicipaddresses")):
        return True
    return False


def _severity_from_text(*values: str, default: str) -> str:
    text = " ".join(values).lower()
    critical_markers = ("public blob", "disable logging", "soft delete", "public network", "delete", "role assignment")
    high_markers = ("key vault", "diagnostic", "network", "firewall", "public")
    if any(marker in text for marker in critical_markers):
        return "Critical"
    if any(marker in text for marker in high_markers):
        return "High"
    return default


def _severity_from_activity(operation: str, resource_id: str, status: str) -> str:
    text = " ".join([operation, resource_id, status]).lower()
    if "delete" in text or "roleassignments" in text or "listkeys" in text or "regeneratekey" in text:
        return "Critical"
    if any(marker in text for marker in ("diagnosticsettings", "firewall", "storageaccounts", "publicip")):
        return "High"
    return "Medium"


def _category_from_text(*values: str) -> str:
    text = " ".join(values).lower()
    if any(marker in text for marker in LOGGING_MARKERS):
        return "Logging and Monitoring"
    if "role" in text or "identity" in text or "permission" in text:
        return "Identity and Access"
    if any(marker in text for marker in PUBLIC_MARKERS):
        return "Network Security"
    if "policy" in text or "compliance" in text:
        return "Cloud Compliance"
    return "Cloud Security Posture"


def _text_has_markers(*values: str, markers: Iterable[str]) -> bool:
    haystack = " ".join(values).lower()
    return any(marker in haystack for marker in markers)


def _data_sensitivity_from_text(*values: str) -> str:
    haystack = " ".join(values).lower()
    if any(marker in haystack for marker in ("pii", "personal", "regulated")):
        return "regulated"
    if any(marker in haystack for marker in SENSITIVE_MARKERS):
        return "confidential"
    return "internal"


def _asset_criticality_from_text(*values: str) -> str:
    haystack = " ".join(values).lower()
    if any(marker in haystack for marker in ("keyvault", "vault", "sql", "database", "roleassignments")):
        return "critical"
    if any(marker in haystack for marker in ("storage", "network", "firewall", "publicip")):
        return "high"
    return "medium"


def _stable_finding_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(":".join(part for part in parts if part).encode("utf-8")).hexdigest()[:10].upper()
    return f"{prefix}-{digest}"


def _nested_value(record: Dict[str, Any], *keys: str) -> str:
    current: Any = record
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return str(current) if current not in (None, "") else ""


def _count_findings_by_source(findings: Iterable[NormalizedFinding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.source_tool] = counts.get(finding.source_tool, 0) + 1
    return counts


def _merge_counts(base: Dict[str, int], extra: Dict[str, int]) -> Dict[str, int]:
    merged = dict(base)
    for key, value in extra.items():
        merged[key] = merged.get(key, 0) + value
    return merged


def _deduplicate_findings(findings: Iterable[NormalizedFinding]) -> List[NormalizedFinding]:
    deduped: Dict[str, NormalizedFinding] = {}
    for finding in findings:
        deduped[finding.finding_id] = finding
    return list(deduped.values())


def _find_prowler_output_candidates(directory: Path, filename_prefix: str) -> List[Path]:
    json_candidates = sorted(
        [
            path
            for path in directory.rglob("*.json")
            if "compliance" not in {part.lower() for part in path.parts}
            and (filename_prefix in path.name or "prowler-output" in path.name.lower())
        ],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if json_candidates:
        return json_candidates[:3]

    csv_candidates = sorted(
        [
            path
            for path in directory.rglob("*.csv")
            if "compliance" not in {part.lower() for part in path.parts}
            and (filename_prefix in path.name or "prowler-output" in path.name.lower())
        ],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return csv_candidates[:3]


def _prowler_auth_flag(credential_label: str, auth_mode: str) -> str:
    if credential_label == "environment":
        return "--sp-env-auth"
    if credential_label == "managed_identity":
        return "--managed-identity-auth"
    if auth_mode == "env":
        return "--sp-env-auth"
    return "--az-cli-auth"
