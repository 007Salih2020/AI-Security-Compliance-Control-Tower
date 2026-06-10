from app.database import get_db
from app.models import ModelInventoryRecord, utcnow_iso


def _record(model_id: str, source: str) -> ModelInventoryRecord:
    now = utcnow_iso()
    return ModelInventoryRecord(
        model_inventory_id=model_id,
        model_name=model_id.lower(),
        deployment_name=model_id.lower(),
        provider="Test",
        platform="Test Platform",
        subscription_id="sub",
        resource_group="rg",
        region="westeurope",
        endpoint="",
        model_family="test",
        model_version="1",
        deployment_type="test",
        environment="production",
        owner="unknown",
        business_unit="unknown",
        application_name="app",
        use_case="unknown",
        data_classification="internal",
        processes_personal_data=False,
        processes_confidential_data=False,
        internet_accessible=False,
        private_network_enabled=True,
        logging_enabled=True,
        content_filtering_enabled=True,
        evaluation_available=False,
        red_team_tested=False,
        used_by_agent=False,
        approval_status="needs_review",
        discovered_at=now,
        last_seen=now,
        source=source,
    )


def test_replace_models_overwrites_existing_registry_and_prunes_model_reports():
    db = get_db()
    db.save_models([_record("MODEL-LOCAL", "local_sample")])
    db.replace_models([_record("MODEL-AZURE", "azure_live")])

    models = db.get_models()

    assert len(models) == 1
    assert models[0].model_inventory_id == "MODEL-AZURE"
