from __future__ import annotations

import json

from scanners.prowler_adapter import parse_prowler_file


def test_parse_native_prowler_ocsf_output(tmp_path):
    prowler_output = [
        {
            "status": "FAIL",
            "time": "2026-06-05T12:00:00Z",
            "severity": {"label": "high"},
            "finding_info": {
                "uid": "prowler-azure-storage-public",
                "title": "Storage account allows public blob access",
                "description": "The storage account permits anonymous blob access over the internet.",
            },
            "resources": [
                {
                    "uid": "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/publicdata001",
                    "name": "publicdata001",
                    "type": "Microsoft.Storage/storageAccounts",
                }
            ],
            "cloud": {
                "provider": "azure",
                "account": {"uid": "sub-1"},
            },
            "remediation": {
                "desc": "Disable public blob access and restrict public network access.",
                "references": ["https://learn.microsoft.com/example"],
            },
            "compliance": {"ISO 27001": ["A.8.20"], "CIS": ["3.3"]},
        }
    ]
    output_path = tmp_path / "prowler-output.json"
    output_path.write_text(json.dumps(prowler_output), encoding="utf-8")

    findings = parse_prowler_file(output_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "Prowler"
    assert finding.severity == "High"
    assert finding.provider == "Azure"
    assert finding.resource_name == "publicdata001"
    assert finding.internet_exposure is True
    assert "ISO 27001" in finding.compliance_frameworks

