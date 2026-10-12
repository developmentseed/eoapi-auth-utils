from collections.abc import Sequence

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class OpenIdConnectSettings(BaseSettings):
    # Swagger UI config for Authorization Code Flow
    client_id: str = ""
    use_pkce: bool = True
    openid_configuration_url: AnyHttpUrl | None = None
    openid_configuration_internal_url: AnyHttpUrl | None = None

    allowed_jwt_audiences: Sequence[str] | None = []

    # Token validation, see OpenIdConnectAuth
    issuer: str | None = None
    required_claims: Sequence[str] = ("exp", "iss")

    model_config = SettingsConfigDict(
        env_prefix="EOAPI_AUTH_",
        env_file=".env",
        extra="allow",
    )
