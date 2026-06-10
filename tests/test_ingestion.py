from app.services import ingest_demo, reset_state


def test_ingest_demo_loads_all_sample_findings():
    reset_state(clear_reports=True)
    findings = ingest_demo()
    ids = {finding.finding_id for finding in findings}

    assert len(findings) == 6
    assert {"AZURE-001", "AZURE-002", "AZURE-003", "GITHUB-001", "SBOM-001", "AI-AGENT-001"} == ids
