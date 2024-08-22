import json
import logging
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, Callable, Optional, Sequence

import jwt
from fastapi import HTTPException, Security, routing, security, status
from fastapi.dependencies.utils import get_parameterless_sub_dependant
from fastapi.security.base import SecurityBase
from pydantic import AnyHttpUrl

from .errors import OidcFetchError

if TYPE_CHECKING:
    from .config import OpenIdConnectSettings

logger = logging.getLogger(__name__)


@dataclass
class OpenIdConnectAuth:
    openid_configuration_url: AnyHttpUrl
    openid_configuration_internal_url: Optional[AnyHttpUrl] = None
    allowed_jwt_audiences: Optional[Sequence[str]] = None

    # Generated attributes
    auth_scheme: SecurityBase = field(init=False)
    jwks_client: jwt.PyJWKClient = field(init=False)
    valid_token_dependency: Callable[..., Any] = field(init=False)

    def __post_init__(self):
        logger.debug("Requesting OIDC config")
        with urllib.request.urlopen(
            str(self.openid_configuration_internal_url or self.openid_configuration_url)
        ) as response:
            if response.status != 200:
                logger.error(
                    "Received a non-200 response when fetching OIDC config: %s",
                    response.text,
                )
                raise OidcFetchError(
                    f"Request for OIDC config failed with status {response.status}"
                )
            oidc_config = json.load(response)
            self.jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

        self.auth_scheme = security.OpenIdConnect(
            openIdConnectUrl=str(self.openid_configuration_url)
        )
        self.valid_token_dependency = self.create_auth_token_dependency(
            auth_scheme=self.auth_scheme,
            jwks_client=self.jwks_client,
            allowed_jwt_audiences=self.allowed_jwt_audiences,
        )

    @classmethod
    def from_settings(cls, settings: "OpenIdConnectSettings") -> "OpenIdConnectAuth":
        return cls(**settings.model_dump(include=cls.__dataclass_fields__.keys()))

    @staticmethod
    def create_auth_token_dependency(
        auth_scheme: SecurityBase,
        jwks_client: jwt.PyJWKClient,
        allowed_jwt_audiences: Sequence[str],
    ):
        """
        Create a dependency that validates JWT tokens & scopes.
        """

        def auth_token(
            auth_header: Annotated[str, Security(auth_scheme)],
            required_scopes: security.SecurityScopes,
        ):
            # Extract token from header
            token_parts = auth_header.split(" ")
            if len(token_parts) != 2 or token_parts[0].lower() != "bearer":
                logger.error(f"Invalid token: {auth_header}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            [_, token] = token_parts

            # Parse & validate token
            try:
                key = jwks_client.get_signing_key_from_jwt(token).key
                payload = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    # NOTE: Audience validation MUST match audience claim if set in token (https://pyjwt.readthedocs.io/en/stable/changelog.html?highlight=audience#id40)
                    audience=allowed_jwt_audiences,
                )
            except (jwt.exceptions.InvalidTokenError, jwt.exceptions.DecodeError) as e:
                logger.exception(f"InvalidTokenError: {e=}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from e

            # Validate scopes (if required)
            for scope in required_scopes.scopes:
                if scope not in payload["scope"]:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not enough permissions",
                        headers={
                            "WWW-Authenticate": f'Bearer scope="{required_scopes.scope_str}"'
                        },
                    )

            return payload

        return auth_token

    def apply_auth_dependencies(
        self,
        api_route: routing.APIRoute,
        required_token_scopes: Optional[Sequence[str]] = None,
        dependency: Optional[Callable[..., Any]] = None,
    ):
        """
        Apply auth dependencies to a route.
        """
        # Ignore paths without dependants, e.g. /api, /api.html, /docs/oauth2-redirect
        if not hasattr(api_route, "dependant"):
            logger.warning(
                f"Route {api_route} has no dependant, not apply auth dependency"
            )
            return

        depends = Security(
            dependency or self.valid_token_dependency, scopes=required_token_scopes
        )
        logger.debug(f"{depends} -> {','.join(api_route.methods)} @ {api_route.path}")

        # Mimicking how APIRoute handles dependencies:
        # https://github.com/tiangolo/fastapi/blob/1760da0efa55585c19835d81afa8ca386036c325/fastapi/routing.py#L408-L412
        api_route.dependant.dependencies.insert(
            0,
            get_parameterless_sub_dependant(
                depends=depends, path=api_route.path_format
            ),
        )

        # Register dependencies directly on route so that they aren't ignored if
        # the routes are later associated with an app (e.g.
        # app.include_router(router))
        # https://github.com/tiangolo/fastapi/blob/58ab733f19846b4875c5b79bfb1f4d1cb7f4823f/fastapi/applications.py#L337-L360
        # https://github.com/tiangolo/fastapi/blob/58ab733f19846b4875c5b79bfb1f4d1cb7f4823f/fastapi/routing.py#L677-L678
        api_route.dependencies.extend([depends])
