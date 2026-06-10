from app.services import discover_and_register_models, reset_state


def test_local_model_discovery_returns_five_records():
    reset_state(clear_reports=True)
    models = discover_and_register_models(source="local")

    assert len(models) == 5
    assert sum(1 for model in models if model.owner.lower() == "unknown") == 2
