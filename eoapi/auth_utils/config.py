from typing import Optional, Sequence

from pydantic import AnyHttpUrl

try:
    from pydantic.v1 import BaseSettings  # type:ignore
except ImportError:
    from pydantic import BaseSettings  # type:ignore


class OpenIdConnectSettings(BaseSettings):
    # Swagger UI config for Authorization Code Flow
    client_id: str = ""
    use_pkce: bool = True
    openid_configuration_url: Optional[AnyHttpUrl] = None
    openid_configuration_internal_url: Optional[AnyHttpUrl] = None

    allowed_jwt_audiences: Optional[Sequence[str]] = []

    model_config = {
        "env_prefix": "EOAPI_AUTH_",
        "env_file": ".env",
        "extra": "allow",
    }
