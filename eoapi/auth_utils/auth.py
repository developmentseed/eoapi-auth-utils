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


def _decode(
    token: str,
    jwks_client: jwt.PyJWKClient,
    allowed_jwt_audiences: Sequence[str] | None,
    issuer: str | None,
    required_claims: Sequence[str],
) -> dict[str, Any]:
    """Return the validated token payload or raise jwt.PyJWTError."""
    key = jwks_client.get_signing_key_from_jwt(token).key
    # PyJWT treats a missing `iss` as an error whenever `issuer` is given; only let
    # it do so when `iss` is required, otherwise verify `iss` only if present.
    iss_required = "iss" in required_claims
    payload = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        # NOTE: Audience validation MUST match audience claim if set in token (https://pyjwt.readthedocs.io/en/stable/changelog.html?highlight=audience#id40)
        audience=allowed_jwt_audiences or None,
        issuer=issuer if iss_required else None,
        options={"require": list(required_claims)},
    )
    if issuer and not iss_required and "iss" in payload and payload["iss"] != issuer:
        raise jwt.exceptions.InvalidIssuerError("Invalid issuer")
    return payload


def _validate_header(
    auth_header: str | None,
    required_scopes: security.SecurityScopes,
    get_validator: Callable[[], Callable[[str], dict[str, Any]]],
) -> dict[str, Any] | None:
    """Validate an Authorization header; None when there is no header."""
    if not auth_header:
        return None

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
    validate = get_validator()
    try:
        payload = validate(token)
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

        issuer = self.issuer or oidc_config.get("issuer")
        if not issuer and "iss" in self.required_claims:
            raise OidcFetchError(
                "OIDC config has no issuer; set `issuer` or remove 'iss' from "
                "`required_claims`"
            )
        self.issuer = issuer
        self.jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

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

    @staticmethod
    def create_auth_token_dependency(
        auth_scheme: SecurityBase,
        jwks_client: jwt.PyJWKClient,
        allowed_jwt_audiences: Sequence[str] | None,
        *,
        issuer: str | None = None,
        required_claims: Sequence[str] = (),
    ):
        """
        Create a dependency that validates JWT tokens & scopes.
        """

        def get_validator() -> Callable[[str], dict[str, Any]]:
            def validate(token: str) -> dict[str, Any]:
                return _decode(
                    token, jwks_client, allowed_jwt_audiences, issuer, required_claims
                )

            return validate

        def auth_token(
            auth_header: Annotated[str, Security(auth_scheme)],
            required_scopes: security.SecurityScopes,
        ):
            payload = _validate_header(auth_header, required_scopes, get_validator)
            if payload is None:
                raise _unauthorized("Not authenticated")
            return payload

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
