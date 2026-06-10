from app.config import get_settings


def test_azure_openai_key_alias_is_supported(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_KEY", "alias-key")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

    settings = get_settings()

    assert settings.azure_openai_api_key == "alias-key"


def test_azure_auth_mode_is_loaded(monkeypatch):
    monkeypatch.setenv("AZURE_AUTH_MODE", "cli")

    settings = get_settings()

    assert settings.azure_auth_mode == "cli"
