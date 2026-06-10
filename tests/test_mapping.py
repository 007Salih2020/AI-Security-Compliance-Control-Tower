from app.services import ingest_demo, reset_state


def test_control_mapper_attaches_logging_control():
    reset_state(clear_reports=True)
    findings = ingest_demo()
    azure_logging = next(finding for finding in findings if finding.finding_id == "AZURE-003")
    control_ids = {control.control_id for control in azure_logging.mapped_controls}

    assert "A.12.4" in control_ids
    assert "AU-2" in control_ids
    assert "CIS-08" in control_ids
