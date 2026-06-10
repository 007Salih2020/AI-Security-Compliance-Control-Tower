from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence

import requests
from azure.core.credentials import TokenCredential
from azure.identity import AzureCliCredential, DefaultAzureCredential, EnvironmentCredential, ManagedIdentityCredential

from app.config import get_settings
from app.models import ModelInventoryRecord, utcnow_iso

try:
    from azure.ai.ml import MLClient
except ImportError:  # pragma: no cover - installed in live runtime
    MLClient = None

MANAGEMENT_SCOPE = "https://management.azure.com/.default"
RESOURCE_GRAPH_API_VERSION = "2024-04-01"
AI_SERVICES_DEPLOYMENTS_API_VERSION = "2024-10-01"
DIAGNOSTIC_SETTINGS_API_VERSION = "2021-05-01-preview"


@dataclass(slots=True)
class AzureDiscoveryResult:
    models: List[ModelInventoryRecord]
    mode: str
    message: str


class AzureDiscoveryError(RuntimeError):
    """Raised when live Azure discovery cannot be completed."""


class AzureArmRequestError(AzureDiscoveryError):
    def __init__(self, method: str, url: str, status_code: int, response_text: str) -> None:
        self.method = method
        self.url = url
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(f"Azure ARM {method} failed for {url}: {status_code} {response_text}")


class AzureDiscoveryAdapter:
    """
    Live Azure discovery for AI inventories.

    Authentication uses DefaultAzureCredential, which means any of the following can
    work without code changes:
    - service principal values in .env
    - az login on the local workstation
    - managed identity when deployed on Azure
    """

    def __init__(self, force_live: bool = False) -> None:
        self.settings = get_settings()
        self.force_live = force_live
        self.credential: TokenCredential | None = None
        self.credential_label = "uninitialized"
        self._session = requests.Session()
        self._arm_token: str | None = None

    def discover(self) -> AzureDiscoveryResult:
        if not self.force_live and not self.settings.enable_azure_discovery:
            return AzureDiscoveryResult(
                models=[],
                mode="disabled",
                message="Azure discovery is disabled. Set ENABLE_AZURE_DISCOVERY=true or call source=azure explicitly.",
            )

        subscriptions = self._resolve_subscription_ids()
        errors: List[str] = []
        best_result: AzureDiscoveryResult | None = None

        for credential_label, credential in self._credential_candidates():
            self.credential = credential
            self.credential_label = credential_label
            self._arm_token = None

            try:
                result = self._discover_with_current_credential(subscriptions)
                if self.settings.azure_auth_mode != "auto":
                    return result
                if best_result is None or len(result.models) > len(best_result.models):
                    best_result = result
                if credential_label == "azure_cli":
                    return best_result
            except AzureDiscoveryError as exc:
                errors.append(f"{credential_label}: {exc}")
                if self.settings.azure_auth_mode != "auto" or not self._is_retryable_credential_error(exc):
                    raise

        if best_result is not None:
            return best_result
        if errors:
            raise AzureDiscoveryError(
                "Azure discovery failed for every configured credential path. "
                + " | ".join(errors)
            )
        raise AzureDiscoveryError("Azure discovery could not find a usable Azure credential.")

    def _discover_with_current_credential(self, subscriptions: Sequence[str]) -> AzureDiscoveryResult:
        self._arm_token = self._get_management_token()
        arg_rows = self._query_resource_graph(
            """
            Resources
            | where type in~ (
                'microsoft.cognitiveservices/accounts',
                'microsoft.machinelearningservices/workspaces'
              )
            | project id, name, type, kind, location, subscriptionId, resourceGroup, tags, properties
            """,
            subscriptions=subscriptions,
        )
        cognitive_accounts = [row for row in arg_rows if str(row.get("type", "")).lower() == "microsoft.cognitiveservices/accounts"]
        aml_workspaces = [
            row for row in arg_rows if str(row.get("type", "")).lower() == "microsoft.machinelearningservices/workspaces"
        ]

        records: List[ModelInventoryRecord] = []
        records.extend(self._discover_azure_openai_deployments(cognitive_accounts))
        records.extend(self._discover_azure_ml_inventory(aml_workspaces))

        deduped = self._deduplicate_records(records)
        return AzureDiscoveryResult(
            models=deduped,
            mode=f"live:{self.credential_label}",
            message=(
                f"Discovered {len(deduped)} live Azure AI/ML inventory records across "
                f"{len(subscriptions)} subscription(s) using {self.credential_label} auth."
            ),
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

    def _is_retryable_credential_error(self, exc: AzureDiscoveryError) -> bool:
        if isinstance(exc, AzureArmRequestError):
            return exc.status_code in {401, 403}

        message = str(exc).lower()
        retryable_markers = (
            "authentication failed",
            "credential",
            "authorization",
            "access is denied",
            "permission",
            "forbidden",
            "unauthorized",
            "403",
            "401",
        )
        return any(marker in message for marker in retryable_markers)

    def _resolve_subscription_ids(self) -> List[str]:
        configured = [
            item.strip()
            for item in self.settings.azure_subscription_id.split(",")
            if item.strip()
        ]
        if configured:
            return configured

        cli_ids = self._subscription_ids_from_cli()
        if cli_ids:
            return cli_ids

        raise AzureDiscoveryError(
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
            raise AzureDiscoveryError("Azure credential is not initialized.")
        try:
            return self.credential.get_token(MANAGEMENT_SCOPE).token
        except Exception as exc:  # pragma: no cover - depends on external auth
            raise AzureDiscoveryError(
                f"Azure authentication failed for credential mode {self.credential_label}. "
                "Verify AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET or run az login."
            ) from exc

    def _headers(self) -> Dict[str, str]:
        if not self._arm_token:
            raise AzureDiscoveryError("Azure access token is not initialized.")
        return {
            "Authorization": f"Bearer {self._arm_token}",
            "Content-Type": "application/json",
        }

    def _arm_get(self, url_or_path: str, api_version: str) -> Dict[str, Any]:
        url = url_or_path if url_or_path.startswith("https://") else f"https://management.azure.com{url_or_path}"
        response = self._session.get(url, headers=self._headers(), params={"api-version": api_version}, timeout=45)
        if response.status_code == 404:
            return {}
        if response.status_code >= 400:
            raise AzureArmRequestError("GET", url, response.status_code, response.text)
        return response.json()

    def _arm_post(self, path: str, api_version: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"https://management.azure.com{path}"
        response = self._session.post(
            url,
            headers=self._headers(),
            params={"api-version": api_version},
            json=payload,
            timeout=45,
        )
        if response.status_code >= 400:
            raise AzureArmRequestError("POST", url, response.status_code, response.text)
        return response.json()

    def _query_resource_graph(self, query: str, subscriptions: Sequence[str]) -> List[Dict[str, Any]]:
        payload = {"subscriptions": list(subscriptions), "query": query}
        response = self._arm_post(
            path="/providers/Microsoft.ResourceGraph/resources",
            api_version=RESOURCE_GRAPH_API_VERSION,
            payload=payload,
        )
        data = response.get("data", [])
        return data if isinstance(data, list) else []

    def _diagnostic_settings_enabled(self, resource_id: str) -> bool:
        result = self._arm_get(
            f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings",
            api_version=DIAGNOSTIC_SETTINGS_API_VERSION,
        )
        values = result.get("value", [])
        return bool(values)

    def _discover_azure_openai_deployments(self, accounts: Sequence[Dict[str, Any]]) -> List[ModelInventoryRecord]:
        records: List[ModelInventoryRecord] = []
        for account in accounts:
            kind = str(account.get("kind", "")).lower()
            if "openai" not in kind and "aiservices" not in kind:
                continue

            account_id = str(account["id"])
            tags = _normalize_tags(account.get("tags"))
            properties = account.get("properties") or {}
            endpoint = str(properties.get("endpoint", ""))
            diagnostic_enabled = self._diagnostic_settings_enabled(account_id)
            private_endpoint_connections = properties.get("privateEndpointConnections") or []
            public_network_access = str(properties.get("publicNetworkAccess", "Enabled")).lower()
            private_network_enabled = bool(private_endpoint_connections) or public_network_access == "disabled"
            internet_accessible = not private_network_enabled and public_network_access != "disabled"

            deployments_payload = self._arm_get(
                f"{account_id}/deployments",
                api_version=AI_SERVICES_DEPLOYMENTS_API_VERSION,
            )
            for deployment in deployments_payload.get("value", []):
                deployment_props = deployment.get("properties") or {}
                deployment_tags = _merge_tags(tags, _normalize_tags(deployment.get("tags")))
                model_info = deployment_props.get("model") or {}
                deployment_name = str(deployment.get("name", "unknown-deployment"))
                model_name = str(model_info.get("name") or deployment_name)
                model_version = str(model_info.get("version") or deployment_props.get("version") or "")
                owner = _tag_value(deployment_tags, "owner", "model_owner", "app_owner", "technical_owner", default="unknown")
                business_unit = _tag_value(deployment_tags, "business_unit", "businessunit", "cost_center", default="unknown")
                use_case = _tag_value(deployment_tags, "use_case", "usecase", "business_purpose", default="unknown")
                app_name = _tag_value(
                    deployment_tags,
                    "application_name",
                    "app_name",
                    "application",
                    "app",
                    default=str(account.get("name", deployment_name)),
                )
                data_classification = _normalize_classification(
                    _tag_value(
                        deployment_tags,
                        "data_classification",
                        "classification",
                        "data_sensitivity",
                        default="internal",
                    )
                )
                content_filtering_enabled = _content_filter_enabled(deployment_props, deployment_tags)
                used_by_agent = _infer_used_by_agent(deployment_tags, app_name, use_case)
                approval_status = _normalize_approval_status(
                    _tag_value(deployment_tags, "approval_status", "approved", "governance_status", default="needs_review")
                )
                environment = _infer_environment(
                    _tag_value(deployment_tags, "environment", "env", default=""),
                    deployment_name,
                    str(account.get("resourceGroup", "")),
                    app_name,
                )
                processes_personal_data, processes_confidential_data = _classify_data_flags(data_classification, deployment_tags)
                evaluation_available = _tag_bool(deployment_tags, "evaluation_available", "evaluated", default=False)
                red_team_tested = _tag_bool(deployment_tags, "red_team_tested", "redteam", default=False)

                records.append(
                    ModelInventoryRecord(
                        model_inventory_id=_stable_inventory_id("AZOAI", f"{account_id}:{deployment_name}"),
                        model_name=model_name,
                        deployment_name=deployment_name,
                        provider="Azure OpenAI",
                        platform="Azure AI Services",
                        subscription_id=str(account.get("subscriptionId", "")),
                        resource_group=str(account.get("resourceGroup", "")),
                        region=str(account.get("location", "")),
                        endpoint=endpoint,
                        model_family=_infer_model_family(model_name),
                        model_version=model_version,
                        deployment_type=str(model_info.get("format") or "azure_openai_deployment"),
                        environment=environment,
                        owner=owner,
                        business_unit=business_unit,
                        application_name=app_name,
                        use_case=use_case,
                        data_classification=data_classification,
                        processes_personal_data=processes_personal_data,
                        processes_confidential_data=processes_confidential_data,
                        internet_accessible=internet_accessible,
                        private_network_enabled=private_network_enabled,
                        logging_enabled=diagnostic_enabled,
                        content_filtering_enabled=content_filtering_enabled,
                        evaluation_available=evaluation_available,
                        red_team_tested=red_team_tested,
                        used_by_agent=used_by_agent,
                        approval_status=approval_status,
                        discovered_at=utcnow_iso(),
                        last_seen=utcnow_iso(),
                        source="azure_live",
                        tags=deployment_tags,
                        public_endpoint=internet_accessible and not private_network_enabled,
                    )
                )
        return records

    def _discover_azure_ml_inventory(self, workspaces: Sequence[Dict[str, Any]]) -> List[ModelInventoryRecord]:
        if MLClient is None:
            return []

        records: List[ModelInventoryRecord] = []
        for workspace in workspaces:
            workspace_id = str(workspace["id"])
            workspace_name = str(workspace["name"])
            subscription_id = str(workspace.get("subscriptionId", ""))
            resource_group = str(workspace.get("resourceGroup", ""))
            location = str(workspace.get("location", ""))
            workspace_tags = _normalize_tags(workspace.get("tags"))
            workspace_props = workspace.get("properties") or {}
            public_network_access = str(workspace_props.get("publicNetworkAccess", "Enabled")).lower()
            private_network_enabled = public_network_access == "disabled"
            workspace_logging = self._diagnostic_settings_enabled(workspace_id)

            try:
                ml_client = MLClient(self.credential, subscription_id, resource_group, workspace_name)
            except Exception as exc:  # pragma: no cover - depends on external service
                raise AzureDiscoveryError(f"Failed to create MLClient for workspace {workspace_name}: {exc}") from exc

            discovered_deployment_keys: set[str] = set()

            try:
                endpoints = list(ml_client.online_endpoints.list())
            except Exception as exc:  # pragma: no cover - depends on external service
                raise AzureDiscoveryError(f"Failed to list AML endpoints for workspace {workspace_name}: {exc}") from exc

            for endpoint in endpoints:
                endpoint_tags = _merge_tags(workspace_tags, _normalize_tags(getattr(endpoint, "tags", None)))
                endpoint_name = str(getattr(endpoint, "name", "unknown-endpoint"))
                endpoint_uri = str(getattr(endpoint, "scoring_uri", "") or "")
                endpoint_env = _infer_environment(
                    _tag_value(endpoint_tags, "environment", "env", default=""),
                    endpoint_name,
                    resource_group,
                    workspace_name,
                )
                endpoint_app = _tag_value(endpoint_tags, "application_name", "app_name", "application", default=workspace_name)
                endpoint_use_case = _tag_value(endpoint_tags, "use_case", "usecase", default="unknown")

                try:
                    deployments = list(ml_client.online_deployments.list(endpoint_name=endpoint_name))
                except Exception:
                    deployments = []

                for deployment in deployments:
                    deployment_name = str(getattr(deployment, "name", "unknown-deployment"))
                    deployment_tags = _merge_tags(endpoint_tags, _normalize_tags(getattr(deployment, "tags", None)))
                    model_ref = str(getattr(deployment, "model", "") or "")
                    model_name, model_version = _parse_model_reference(model_ref)
                    if not model_name:
                        model_name = deployment_name

                    data_classification = _normalize_classification(
                        _tag_value(
                            deployment_tags,
                            "data_classification",
                            "classification",
                            default="internal",
                        )
                    )
                    processes_personal_data, processes_confidential_data = _classify_data_flags(data_classification, deployment_tags)
                    model_family = _infer_model_family(model_name)
                    records.append(
                        ModelInventoryRecord(
                            model_inventory_id=_stable_inventory_id("AZMLDEP", f"{workspace_id}:{endpoint_name}:{deployment_name}"),
                            model_name=model_name,
                            deployment_name=deployment_name,
                            provider="Azure ML",
                            platform="Azure Machine Learning",
                            subscription_id=subscription_id,
                            resource_group=resource_group,
                            region=location,
                            endpoint=endpoint_uri,
                            model_family=model_family,
                            model_version=model_version,
                            deployment_type="online_deployment",
                            environment=endpoint_env,
                            owner=_tag_value(deployment_tags, "owner", "model_owner", default="unknown"),
                            business_unit=_tag_value(deployment_tags, "business_unit", "cost_center", default="unknown"),
                            application_name=endpoint_app,
                            use_case=endpoint_use_case,
                            data_classification=data_classification,
                            processes_personal_data=processes_personal_data,
                            processes_confidential_data=processes_confidential_data,
                            internet_accessible=bool(endpoint_uri) and not private_network_enabled,
                            private_network_enabled=private_network_enabled,
                            logging_enabled=workspace_logging,
                            content_filtering_enabled=_content_filtering_required(model_family) is False
                            or _tag_bool(deployment_tags, "content_filtering_enabled", "content_filtering", default=True),
                            evaluation_available=_tag_bool(deployment_tags, "evaluation_available", "evaluated", default=False),
                            red_team_tested=_tag_bool(deployment_tags, "red_team_tested", "redteam", default=False),
                            used_by_agent=_infer_used_by_agent(deployment_tags, endpoint_app, endpoint_use_case),
                            approval_status=_normalize_approval_status(
                                _tag_value(deployment_tags, "approval_status", "approved", default="needs_review")
                            ),
                            discovered_at=utcnow_iso(),
                            last_seen=utcnow_iso(),
                            source="azure_live",
                            tags=deployment_tags,
                            public_endpoint=bool(endpoint_uri) and not private_network_enabled,
                        )
                    )
                    discovered_deployment_keys.add(f"{model_name}:{model_version}")

            try:
                models = list(ml_client.models.list())
            except Exception:
                models = []

            for model in models:
                model_name = str(getattr(model, "name", "unknown-model"))
                model_version = str(getattr(model, "version", "") or "")
                if f"{model_name}:{model_version}" in discovered_deployment_keys:
                    continue

                model_tags = _merge_tags(workspace_tags, _normalize_tags(getattr(model, "tags", None)))
                data_classification = _normalize_classification(
                    _tag_value(model_tags, "data_classification", "classification", default="internal")
                )
                processes_personal_data, processes_confidential_data = _classify_data_flags(data_classification, model_tags)
                model_family = _infer_model_family(model_name)
                records.append(
                    ModelInventoryRecord(
                        model_inventory_id=_stable_inventory_id("AZMLMOD", f"{workspace_id}:{model_name}:{model_version}"),
                        model_name=model_name,
                        deployment_name="registered-model",
                        provider="Azure ML",
                        platform="Azure Machine Learning",
                        subscription_id=subscription_id,
                        resource_group=resource_group,
                        region=location,
                        endpoint="",
                        model_family=model_family,
                        model_version=model_version,
                        deployment_type="registered_model",
                        environment=_infer_environment(
                            _tag_value(model_tags, "environment", "env", default=""),
                            model_name,
                            resource_group,
                            workspace_name,
                        ),
                        owner=_tag_value(model_tags, "owner", "model_owner", default="unknown"),
                        business_unit=_tag_value(model_tags, "business_unit", "cost_center", default="unknown"),
                        application_name=_tag_value(model_tags, "application_name", "app_name", default=workspace_name),
                        use_case=_tag_value(model_tags, "use_case", "usecase", default="unknown"),
                        data_classification=data_classification,
                        processes_personal_data=processes_personal_data,
                        processes_confidential_data=processes_confidential_data,
                        internet_accessible=False,
                        private_network_enabled=private_network_enabled,
                        logging_enabled=workspace_logging,
                        content_filtering_enabled=_content_filtering_required(model_family) is False
                        or _tag_bool(model_tags, "content_filtering_enabled", "content_filtering", default=True),
                        evaluation_available=_tag_bool(model_tags, "evaluation_available", "evaluated", default=False),
                        red_team_tested=_tag_bool(model_tags, "red_team_tested", "redteam", default=False),
                        used_by_agent=_infer_used_by_agent(
                            model_tags,
                            _tag_value(model_tags, "application_name", "app_name", default=workspace_name),
                            _tag_value(model_tags, "use_case", "usecase", default="unknown"),
                        ),
                        approval_status=_normalize_approval_status(
                            _tag_value(model_tags, "approval_status", "approved", default="needs_review")
                        ),
                        discovered_at=utcnow_iso(),
                        last_seen=utcnow_iso(),
                        source="azure_live",
                        tags=model_tags,
                        public_endpoint=False,
                    )
                )

        return records

    def _deduplicate_records(self, records: Iterable[ModelInventoryRecord]) -> List[ModelInventoryRecord]:
        deduped: Dict[str, ModelInventoryRecord] = {}
        for record in records:
            deduped[record.model_inventory_id] = record
        return list(deduped.values())


def discover_models_via_azure(force_live: bool = False) -> AzureDiscoveryResult:
    return AzureDiscoveryAdapter(force_live=force_live).discover()


def _stable_inventory_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def _normalize_tags(tags: Any) -> Dict[str, Any]:
    if not isinstance(tags, dict):
        return {}
    normalized: Dict[str, Any] = {}
    for key, value in tags.items():
        normalized[str(key).strip().lower()] = value
    return normalized


def _merge_tags(*tag_sets: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for tag_set in tag_sets:
        merged.update(tag_set)
    return merged


def _tag_value(tags: Dict[str, Any], *names: str, default: str) -> str:
    for name in names:
        candidate = tags.get(name.lower())
        if candidate not in (None, ""):
            return str(candidate).strip()
    return default


def _tag_bool(tags: Dict[str, Any], *names: str, default: bool) -> bool:
    value = _tag_value(tags, *names, default=str(default))
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _normalize_classification(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"public", "internal", "confidential", "regulated"}:
        return normalized
    if normalized in {"personal", "pii", "sensitive"}:
        return "regulated"
    return "internal"


def _normalize_approval_status(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"approved", "pending", "needs_review", "rejected"}:
        return normalized
    if normalized in {"yes", "true"}:
        return "approved"
    return "needs_review"


def _infer_environment(tag_value: str, *hints: str) -> str:
    normalized = tag_value.strip().lower()
    if normalized:
        return normalized
    joined = " ".join(hints).lower()
    for candidate in ["production", "prod", "development", "dev", "test", "qa", "uat", "stage", "staging"]:
        if candidate in joined:
            return "production" if candidate in {"production", "prod"} else candidate
    return "production"


def _classify_data_flags(data_classification: str, tags: Dict[str, Any]) -> tuple[bool, bool]:
    personal = _tag_bool(tags, "processes_personal_data", "personal_data", "pii", default=False)
    confidential = _tag_bool(tags, "processes_confidential_data", "confidential_data", default=False)
    if data_classification == "regulated":
        personal = True
        confidential = True
    elif data_classification == "confidential":
        confidential = True
    return personal, confidential


def _infer_model_family(model_name: str) -> str:
    lowered = model_name.lower()
    for family in ["gpt-4.1", "gpt-4o", "gpt-5", "phi", "llama", "mistral", "bert", "xgboost"]:
        if family in lowered:
            return family
    return model_name


def _infer_used_by_agent(tags: Dict[str, Any], app_name: str, use_case: str) -> bool:
    if _tag_bool(tags, "used_by_agent", "agent", "agent_enabled", default=False):
        return True
    joined = f"{app_name} {use_case}".lower()
    return "agent" in joined or "autonomous" in joined


def _content_filtering_required(model_family: str) -> bool:
    lowered = model_family.lower()
    return any(token in lowered for token in ["gpt", "llama", "mistral", "phi"])


def _content_filter_enabled(properties: Dict[str, Any], tags: Dict[str, Any]) -> bool:
    if _tag_bool(tags, "content_filtering_enabled", "content_filtering", default=False):
        return True
    policy_name = str(properties.get("raiPolicyName") or properties.get("raiPolicy") or "").strip()
    return bool(policy_name)


def _parse_model_reference(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    match = re.search(r"/models/([^/]+)/versions/([^/]+)", value)
    if match:
        return match.group(1), match.group(2)
    return value.rsplit("/", 1)[-1], ""
