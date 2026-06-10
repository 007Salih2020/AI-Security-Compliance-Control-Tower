from types import SimpleNamespace

from models_inventory.azure_discovery import AzureDiscoveryAdapter, AzureDiscoveryResult


def test_auto_auth_prefers_candidate_with_more_inventory(monkeypatch):
    adapter = AzureDiscoveryAdapter(force_live=True)
    adapter.settings.azure_auth_mode = "auto"

    monkeypatch.setattr(adapter, "_resolve_subscription_ids", lambda: ["sub-1"])
    monkeypatch.setattr(adapter, "_credential_candidates", lambda: [("environment", object()), ("azure_cli", object())])

    def fake_discovery(_subscriptions):
        if adapter.credential_label == "environment":
            return AzureDiscoveryResult(models=[], mode="live:environment", message="env")
        return AzureDiscoveryResult(models=[SimpleNamespace(model_inventory_id="MODEL-1")], mode="live:azure_cli", message="cli")

    monkeypatch.setattr(adapter, "_discover_with_current_credential", fake_discovery)

    result = adapter.discover()

    assert result.mode == "live:azure_cli"
    assert len(result.models) == 1
