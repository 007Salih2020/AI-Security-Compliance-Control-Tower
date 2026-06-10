from __future__ import annotations

import json

from scanners.github_artifacts import ingest_github_artifacts


def test_ingest_github_artifacts_from_local_directory(tmp_path, monkeypatch):
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    sarif_payload = {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "GITHUB-ARTIFACT-001",
                        "level": "error",
                        "message": {"text": "Potential secret exposure in repository history"},
                        "properties": {
                            "provider": "GitHub",
                            "service": "Repository",
                            "resource_id": "repo-1",
                            "resource_name": "demo-repo",
                            "category": "Code Security",
                            "created_at": "2026-06-05T12:00:00Z",
                        },
                    }
                ],
            }
        ]
    }
    (artifacts_dir / "codeql-results.sarif").write_text(json.dumps(sarif_payload), encoding="utf-8")

    cyclonedx_payload = {
        "bomFormat": "CycloneDX",
        "metadata": {"timestamp": "2026-06-05T12:00:00Z"},
        "components": [
            {
                "bom-ref": "pkg:pypi/pyjwt@1.7.1",
                "name": "pyjwt",
                "version": "1.7.1",
                "purl": "pkg:pypi/pyjwt@1.7.1",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2026-0001",
                "description": "Critical vulnerable dependency in pyjwt.",
                "ratings": [{"severity": "critical"}],
                "affects": [{"ref": "pkg:pypi/pyjwt@1.7.1"}],
                "recommendation": "Upgrade pyjwt to a fixed release.",
            }
        ],
    }
    (artifacts_dir / "dependency-sbom.json").write_text(json.dumps(cyclonedx_payload), encoding="utf-8")

    monkeypatch.setenv("GITHUB_ARTIFACTS_DIR", str(artifacts_dir))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)

    result = ingest_github_artifacts()
    finding_ids = {finding.finding_id for finding in result.findings}

    assert "GITHUB-ARTIFACT-001" in finding_ids
    assert "CVE-2026-0001" in finding_ids
    assert result.processed_files

