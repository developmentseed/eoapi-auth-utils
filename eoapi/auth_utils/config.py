from typing import Optional, Sequence

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class OpenIdConnectSettings(BaseSettings):
    # Swagger UI config for Authorization Code Flow
    client_id: str = ""
    use_pkce: bool = True
    openid_configuration_url: Optional[AnyHttpUrl] = None
    openid_configuration_internal_url: Optional[AnyHttpUrl] = None

    allowed_jwt_audiences: Optional[Sequence[str]] = []

    # Token validation & discovery, see OpenIdConnectAuth
    issuer: Optional[str] = None
    required_claims: Sequence[str] = ("exp", "iss")
    discovery_timeout: float = 10.0
    lazy_discovery: bool = False

    model_config = SettingsConfigDict(
        env_prefix="EOAPI_AUTH_",
        env_file=".env",
        extra="allow",
    )
