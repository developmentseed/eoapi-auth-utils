import pytest
from fastapi.security import SecurityScopes

from eoapi.auth_utils import OpenIdConnectAuth, OpenIdConnectSettings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    # Don't pick up a developer's .env
    monkeypatch.chdir(tmp_path)


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("EOAPI_AUTH_CLIENT_ID", "my-client")
    monkeypatch.setenv(
        "EOAPI_AUTH_OPENID_CONFIGURATION_URL",
        "https://example.com/.well-known/openid-configuration",
    )
    monkeypatch.setenv("EOAPI_AUTH_ALLOWED_JWT_AUDIENCES", '["a", "b"]')
    monkeypatch.setenv("CLIENT_ID", "unprefixed")

    settings = OpenIdConnectSettings()
    assert settings.client_id == "my-client"
    assert (
        str(settings.openid_configuration_url)
        == "https://example.com/.well-known/openid-configuration"
    )
    assert list(settings.allowed_jwt_audiences) == ["a", "b"]


def test_env_prefix_override(monkeypatch):
    monkeypatch.setenv("AUTH_CLIENT_ID", "other-client")
    monkeypatch.setenv("EOAPI_AUTH_CLIENT_ID", "my-client")
    assert OpenIdConnectSettings(_env_prefix="AUTH_").client_id == "other-client"


def test_env_file(tmp_path):
    (tmp_path / ".env").write_text("EOAPI_AUTH_CLIENT_ID=from-dotenv\n")
    assert OpenIdConnectSettings().client_id == "from-dotenv"


def test_from_settings(monkeypatch, oidc, token_builder):
    monkeypatch.setenv("EOAPI_AUTH_OPENID_CONFIGURATION_URL", oidc.discovery_url)
    monkeypatch.setenv("EOAPI_AUTH_DISCOVERY_TIMEOUT", "2.5")
    auth = OpenIdConnectAuth.from_settings(OpenIdConnectSettings())

    assert auth.discovery_timeout == 2.5
    assert auth.allowed_jwt_audiences is None
    assert auth.required_claims == ("exp", "iss")
    assert auth.openid_configuration == oidc.config

    token = token_builder({"sub": "alice"})
    payload = auth.valid_token_dependency(
        auth_header=f"Bearer {token}", required_scopes=SecurityScopes([])
    )
    assert payload["sub"] == "alice"


def test_from_settings_audiences(oidc):
    settings = OpenIdConnectSettings(
        openid_configuration_url=oidc.discovery_url,
        allowed_jwt_audiences=["eoapi"],
        issuer="https://public.example.com",
    )
    auth = OpenIdConnectAuth.from_settings(settings)
    assert list(auth.allowed_jwt_audiences) == ["eoapi"]
    assert auth.issuer == "https://public.example.com"
