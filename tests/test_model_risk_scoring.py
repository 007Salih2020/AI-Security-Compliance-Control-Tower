from app.services import discover_and_register_models, get_high_risk_models, reset_state


def test_model_risk_scoring_flags_expected_high_risk_models():
    reset_state(clear_reports=True)
    discover_and_register_models(source="local")
    high_risk = {model.model_inventory_id for model in get_high_risk_models()}

    assert high_risk == {"MODEL-001", "MODEL-003"}
