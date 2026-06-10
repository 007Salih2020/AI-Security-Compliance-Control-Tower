from __future__ import annotations

import io
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import requests

from app.config import get_settings
from app.models import NormalizedFinding
from scanners.prowler_adapter import parse_prowler_file
from scanners.sarif_parser import parse_sarif_file
from scanners.sbom_parser import parse_sbom_file


@dataclass(slots=True)
class GitHubArtifactIngestionResult:
    findings: List[NormalizedFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    processed_files: List[str] = field(default_factory=list)


def ingest_github_artifacts() -> GitHubArtifactIngestionResult:
    settings = get_settings()
    result = GitHubArtifactIngestionResult()

    local_dir = settings.github_artifacts_dir
    if local_dir.exists():
        local_result = _load_from_directory(local_dir)
        result.findings.extend(local_result.findings)
        result.warnings.extend(local_result.warnings)
        result.processed_files.extend(local_result.processed_files)
        if result.findings:
            return result

    if not settings.github_token or not settings.github_repository:
        result.warnings.append(
            "GitHub artifact ingestion skipped because GITHUB_TOKEN or GITHUB_REPOSITORY is not configured."
        )
        return result

    remote_result = _load_from_github_api()
    result.findings.extend(remote_result.findings)
    result.warnings.extend(remote_result.warnings)
    result.processed_files.extend(remote_result.processed_files)
    return result


def _load_from_directory(directory: Path) -> GitHubArtifactIngestionResult:
    result = GitHubArtifactIngestionResult()
    if not directory.exists():
        result.warnings.append(f"GitHub artifacts directory does not exist: {directory}")
        return result

    for file_path in sorted(directory.rglob("*")):
        if not file_path.is_file() or not _is_supported_artifact_file(file_path):
            continue
        try:
            result.findings.extend(_parse_artifact_file(file_path))
            result.processed_files.append(str(file_path))
        except Exception as exc:  # pragma: no cover - depends on artifact contents
            result.warnings.append(f"Failed to parse GitHub artifact file {file_path.name}: {exc}")
    return result


def _load_from_github_api() -> GitHubArtifactIngestionResult:
    settings = get_settings()
    result = GitHubArtifactIngestionResult()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {settings.github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    api_root = settings.github_api_url.rstrip("/")
    artifacts_url = f"{api_root}/repos/{settings.github_repository}/actions/artifacts"
    session = requests.Session()

    try:
        response = session.get(artifacts_url, headers=headers, params={"per_page": 100}, timeout=45)
        response.raise_for_status()
    except requests.RequestException as exc:  # pragma: no cover - external network
        result.warnings.append(f"GitHub artifact listing failed: {exc}")
        return result

    payload = response.json()
    artifacts = payload.get("artifacts", [])
    filtered = [
        artifact
        for artifact in artifacts
        if not artifact.get("expired", False) and _artifact_matches_filters(str(artifact.get("name", "")))
    ][: settings.github_artifact_limit]

    if not filtered:
        result.warnings.append("No matching GitHub Actions artifacts were found for SARIF or SBOM ingestion.")
        return result

    with tempfile.TemporaryDirectory(prefix="controllens-gh-artifacts-") as temp_dir:
        temp_root = Path(temp_dir)
        for artifact in filtered:
            artifact_name = str(artifact.get("name", "artifact"))
            archive_url = artifact.get("archive_download_url")
            if not archive_url:
                continue
            try:
                archive_response = session.get(archive_url, headers=headers, timeout=90, allow_redirects=True)
                archive_response.raise_for_status()
                extract_dir = temp_root / artifact_name
                extract_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(archive_response.content)) as archive:
                    archive.extractall(extract_dir)
            except (requests.RequestException, zipfile.BadZipFile) as exc:  # pragma: no cover - external network
                result.warnings.append(f"Failed to download or extract GitHub artifact {artifact_name}: {exc}")
                continue

            extracted = _load_from_directory(extract_dir)
            result.findings.extend(extracted.findings)
            result.warnings.extend(extracted.warnings)
            result.processed_files.extend(extracted.processed_files)
    return result


def _artifact_matches_filters(artifact_name: str) -> bool:
    settings = get_settings()
    filters = [item.strip().lower() for item in settings.github_artifact_names.split(",") if item.strip()]
    if not filters:
        return True
    normalized = artifact_name.strip().lower()
    return any(token in normalized for token in filters)


def _is_supported_artifact_file(path: Path) -> bool:
    name = path.name.lower()
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if ".sarif" in suffixes or name.endswith(".sarif") or name.endswith(".sarif.json"):
        return True
    if "sbom" in name or "cyclonedx" in name or name.endswith("bom.json"):
        return True
    if "prowler" in name:
        return True
    return False


def _parse_artifact_file(path: Path) -> List[NormalizedFinding]:
    name = path.name.lower()
    if ".sarif" in name:
        return parse_sarif_file(path)
    if "sbom" in name or "cyclonedx" in name or name.endswith("bom.json"):
        return parse_sbom_file(path)
    if "prowler" in name:
        return parse_prowler_file(path)
    return []
