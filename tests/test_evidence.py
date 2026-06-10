from pathlib import Path

from app.services import generate_finding_evidence, ingest_demo, replay_governance_trace, reset_state


def test_finding_evidence_is_generated_with_files():
    reset_state(clear_reports=True)
    ingest_demo()
    replay_governance_trace()
    metadata = generate_finding_evidence("AZURE-003")

    assert metadata.evidence_id.startswith("EVID-")
    assert Path(metadata.json_path).exists()
    assert Path(metadata.markdown_path).exists()
