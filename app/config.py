from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "ControlLens AI"))
    environment: str = field(default_factory=lambda: os.getenv("APP_ENV", "local"))
    demo_mode: bool = field(default_factory=lambda: _to_bool(os.getenv("DEMO_MODE"), True))
    enable_azure_discovery: bool = field(default_factory=lambda: _to_bool(os.getenv("ENABLE_AZURE_DISCOVERY"), False))
    data_store_path: Path = field(default_factory=lambda: Path(os.getenv("DATA_STORE_PATH", ROOT_DIR / "data" / "store.json")))
    reports_dir: Path = field(default_factory=lambda: Path(os.getenv("REPORTS_DIR", ROOT_DIR / "reports")))
    samples_dir: Path = field(default_factory=lambda: Path(os.getenv("SAMPLES_DIR", ROOT_DIR / "samples")))
    default_ui_port: int = field(default_factory=lambda: int(os.getenv("UI_PORT", "8503")))
    default_api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))

    azure_tenant_id: str = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID", ""))
    azure_client_id: str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID", ""))
    azure_client_secret: str = field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET", ""))
    azure_subscription_id: str = field(default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID", ""))
    azure_auth_mode: str = field(default_factory=lambda: os.getenv("AZURE_AUTH_MODE", "auto").strip().lower())
    azure_activity_log_lookback_hours: int = field(
        default_factory=lambda: int(os.getenv("AZURE_ACTIVITY_LOG_LOOKBACK_HOURS", "24"))
    )
    azure_policy_query_limit: int = field(default_factory=lambda: int(os.getenv("AZURE_POLICY_QUERY_LIMIT", "200")))

    azure_openai_endpoint: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_ENDPOINT", ""))
    azure_openai_api_key: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_API_KEY", os.getenv("AZURE_OPENAI_KEY", ""))
    )
    azure_openai_deployment: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", ""))
    azure_openai_api_version: str = field(default_factory=lambda: os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"))
    prowler_output_dir: Path = field(
        default_factory=lambda: Path(os.getenv("PROWLER_OUTPUT_DIR", ROOT_DIR / "data" / "prowler-output"))
    )
    prowler_output_filename_prefix: str = field(
        default_factory=lambda: os.getenv("PROWLER_OUTPUT_FILENAME_PREFIX", "controllens-azure-security")
    )
    prowler_binary: str = field(default_factory=lambda: os.getenv("PROWLER_BINARY", "prowler"))
    enable_local_prowler_execution: bool = field(
        default_factory=lambda: _to_bool(os.getenv("ENABLE_LOCAL_PROWLER_EXECUTION"), False)
    )
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    github_repository: str = field(default_factory=lambda: os.getenv("GITHUB_REPOSITORY", ""))
    github_api_url: str = field(default_factory=lambda: os.getenv("GITHUB_API_URL", "https://api.github.com"))
    github_artifacts_dir: Path = field(
        default_factory=lambda: Path(os.getenv("GITHUB_ARTIFACTS_DIR", ROOT_DIR / "data" / "github-artifacts"))
    )
    github_artifact_names: str = field(
        default_factory=lambda: os.getenv("GITHUB_ARTIFACT_NAMES", "sarif,sbom,security,codeql")
    )
    github_artifact_limit: int = field(default_factory=lambda: int(os.getenv("GITHUB_ARTIFACT_LIMIT", "3")))


def get_settings() -> Settings:
    settings = Settings()
    settings.data_store_path.parent.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.samples_dir.mkdir(parents=True, exist_ok=True)
    settings.prowler_output_dir.mkdir(parents=True, exist_ok=True)
    settings.github_artifacts_dir.mkdir(parents=True, exist_ok=True)
    return settings
