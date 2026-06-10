from app.services import discover_and_register_models, get_unknown_owner_models, reset_state, update_model_owner


def test_model_owner_enrichment_updates_registry_and_reduces_unknown_owners():
    reset_state(clear_reports=True)
    discover_and_register_models(source="local")

    updated = update_model_owner(
        "MODEL-001",
        owner="Security AI Team",
        business_unit="Cybersecurity",
        use_case="Security finding triage",
    )

    assert updated.owner == "Security AI Team"
    assert updated.business_unit == "Cybersecurity"
    assert len(get_unknown_owner_models()) == 1
