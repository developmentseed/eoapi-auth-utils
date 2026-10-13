import json
import logging
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Annotated, Any

import jwt
from fastapi import HTTPException, Security, routing, security, status
from fastapi.dependencies.utils import get_parameterless_sub_dependant
from fastapi.security.base import SecurityBase
from pydantic import AnyHttpUrl

from .errors import OidcFetchError

if TYPE_CHECKING:
    from .config import OpenIdConnectSettings

logger = logging.getLogger(__name__)

BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


def _unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=BEARER_CHALLENGE,
    )


def _validate_header(
    auth_header: str,
    required_scopes: security.SecurityScopes,
    jwks_client: jwt.PyJWKClient,
    allowed_jwt_audiences: Sequence[str] | None,
    issuer: str | None,
    required_claims: Sequence[str],
) -> dict[str, Any]:
    """Return the payload of a valid bearer token, or raise 401."""
    # Extract token from header
    token_parts = auth_header.split(" ")
    if (
        len(token_parts) != 2
        or token_parts[0].lower() != "bearer"
        or not token_parts[1]
    ):
        # Never log the header itself, it may contain credentials.
        logger.info("Rejected malformed Authorization header")
        raise _unauthorized()
    [_, token] = token_parts

    # Parse & validate token
    try:
        key = jwks_client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            # NOTE: Audience validation MUST match audience claim if set in token (https://pyjwt.readthedocs.io/en/stable/changelog.html?highlight=audience#id40)
            audience=allowed_jwt_audiences or None,
            # `iss` is only checked when required, so `required_claims=()` also
            # accepts tokens without it.
            issuer=issuer if "iss" in required_claims else None,
            options={"require": list(required_claims)},
        )
    except jwt.exceptions.PyJWTError as e:
        # Exception class only: never log the token.
        logger.info("Rejected bearer token: %s", type(e).__name__)
        raise _unauthorized() from e

    # Validate scopes (if required)
    scope = payload.get("scope")
    granted = scope.split() if isinstance(scope, str) else []
    for required_scope in required_scopes.scopes:
        if required_scope not in granted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={
                    "WWW-Authenticate": f'Bearer scope="{required_scopes.scope_str}"'
                },
            )

    return payload


@dataclass
class OpenIdConnectAuth:
    openid_configuration_url: AnyHttpUrl
    openid_configuration_internal_url: AnyHttpUrl | None = None
    allowed_jwt_audiences: Sequence[str] | None = None

    # Expected `iss` claim; defaults to the `issuer` of the discovery document.
    issuer: str | None = None
    # Claims every token must contain.
    required_claims: Sequence[str] = ("exp", "iss")
    # Timeout (seconds) for the discovery request.
    discovery_timeout: float = 10.0

    # Generated attributes
    auth_scheme: SecurityBase = field(init=False)
    jwks_client: jwt.PyJWKClient = field(init=False)
    valid_token_dependency: Callable[..., Any] = field(init=False)
    openid_configuration: dict[str, Any] | None = field(
        init=False, default=None, repr=False
    )

    def __post_init__(self):
        config = self._fetch_openid_configuration()
        self.issuer = self.issuer or config.get("issuer")
        if not self.issuer and "iss" in self.required_claims:
            raise OidcFetchError(
                "OIDC config has no issuer; set `issuer` or remove 'iss' from "
                "`required_claims`"
            )
        self.jwks_client = jwt.PyJWKClient(config["jwks_uri"])
        self.openid_configuration = config

        self.auth_scheme = security.OpenIdConnect(
            openIdConnectUrl=str(self.openid_configuration_url)
        )
        self.valid_token_dependency = self.create_auth_token_dependency(
            auth_scheme=self.auth_scheme,
            jwks_client=self.jwks_client,
            allowed_jwt_audiences=self.allowed_jwt_audiences,
            issuer=self.issuer,
            required_claims=self.required_claims,
        )

    @classmethod
    def from_settings(cls, settings: "OpenIdConnectSettings") -> "OpenIdConnectAuth":
        if settings.openid_configuration_url is None:
            raise ValueError("openid_configuration_url is required")
        kwargs = settings.model_dump(include={f.name for f in fields(cls)})
        kwargs["allowed_jwt_audiences"] = kwargs["allowed_jwt_audiences"] or None
        return cls(**kwargs)

    def _fetch_openid_configuration(self) -> dict[str, Any]:
        url = str(
            self.openid_configuration_internal_url or self.openid_configuration_url
        )
        logger.debug("Requesting OIDC config")
        try:
            with urllib.request.urlopen(
                url, timeout=self.discovery_timeout
            ) as response:
                config = json.load(response)
        except (OSError, ValueError) as e:
            # HTTP errors, unreachable host, timeouts and invalid JSON
            raise OidcFetchError(f"Request for OIDC config failed: {e}") from e

        if not isinstance(config, dict) or not config.get("jwks_uri"):
            raise OidcFetchError("OIDC config has no jwks_uri")
        return config

    @staticmethod
    def create_auth_token_dependency(
        auth_scheme: SecurityBase,
        jwks_client: jwt.PyJWKClient,
        allowed_jwt_audiences: Sequence[str] | None,
        *,
        issuer: str | None,
        required_claims: Sequence[str],
    ):
        """
        Create a dependency that validates JWT tokens & scopes.

        `issuer` and `required_claims` have no defaults so that callers choose
        them explicitly; `issuer=None, required_claims=()` is the old behaviour.
        """

        def auth_token(
            auth_header: Annotated[str, Security(auth_scheme)],
            required_scopes: security.SecurityScopes,
        ) -> dict[str, Any]:
            return _validate_header(
                auth_header,
                required_scopes,
                jwks_client,
                allowed_jwt_audiences,
                issuer,
                required_claims,
            )

        return auth_token

    def apply_auth_dependencies(
        self,
        api_route: routing.APIRoute,
        required_token_scopes: Sequence[str] | None = None,
        dependency: Callable[..., Any] | None = None,
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
