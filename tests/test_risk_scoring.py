from app.services import ingest_demo, reset_state


def test_finding_risk_scoring_marks_expected_critical_findings():
    reset_state(clear_reports=True)
    findings = ingest_demo()
    ratings = {finding.finding_id: finding.risk_rating for finding in findings}

    assert ratings["AZURE-003"] == "Critical"
    assert ratings["AI-AGENT-001"] == "Critical"
    assert ratings["AZURE-002"] in {"Medium", "High"}
