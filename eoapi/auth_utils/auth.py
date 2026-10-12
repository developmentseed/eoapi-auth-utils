import json
import logging
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from typing import TYPE_CHECKING, Annotated, Any, Callable, Dict, Optional, Sequence

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
    allowed_jwt_audiences: Optional[Sequence[str]],
    issuer: Optional[str],
    required_claims: Sequence[str],
) -> Dict[str, Any]:
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
    auth_header: Optional[str],
    required_scopes: security.SecurityScopes,
    get_validator: Callable[[], Callable[[str], Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
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
    openid_configuration_internal_url: Optional[AnyHttpUrl] = None
    allowed_jwt_audiences: Optional[Sequence[str]] = None

    # Expected `iss` claim; defaults to the `issuer` of the discovery document.
    issuer: Optional[str] = None
    # Claims every token must contain.
    required_claims: Sequence[str] = ("exp", "iss")
    # Timeout (seconds) for the discovery request.
    discovery_timeout: float = 10.0

    # Generated attributes
    auth_scheme: SecurityBase = field(init=False)
    jwks_client: jwt.PyJWKClient = field(init=False)
    valid_token_dependency: Callable[..., Any] = field(init=False)
    optional_token_dependency: Callable[..., Any] = field(init=False)
    openid_configuration: Optional[Dict[str, Any]] = field(
        init=False, default=None, repr=False
    )

    def __post_init__(self):
        self._discovery_lock = threading.Lock()
        self.discover()

        self.auth_scheme = security.OpenIdConnect(
            openIdConnectUrl=str(self.openid_configuration_url)
        )
        self._optional_auth_scheme = security.OpenIdConnect(
            openIdConnectUrl=str(self.openid_configuration_url), auto_error=False
        )
        self.valid_token_dependency = self.create_auth_token_dependency(
            auth_scheme=self.auth_scheme,
            jwks_client=self.jwks_client,
            allowed_jwt_audiences=self.allowed_jwt_audiences,
            issuer=self.issuer,
            required_claims=self.required_claims,
        )
        self.optional_token_dependency = self.create_auth_token_dependency(
            auth_scheme=self._optional_auth_scheme,
            jwks_client=self.jwks_client,
            allowed_jwt_audiences=self.allowed_jwt_audiences,
            issuer=self.issuer,
            required_claims=self.required_claims,
            auto_error=False,
        )

    @classmethod
    def from_settings(cls, settings: "OpenIdConnectSettings") -> "OpenIdConnectAuth":
        init_fields = {f.name for f in dataclass_fields(cls) if f.init}
        kwargs = settings.model_dump(include=init_fields)
        kwargs["allowed_jwt_audiences"] = kwargs.get("allowed_jwt_audiences") or None
        return cls(**{k: v for k, v in kwargs.items() if v is not None})

    @property
    def discovered(self) -> bool:
        """Whether the discovery document has been fetched."""
        return self.openid_configuration is not None

    def _fetch_openid_configuration(self) -> Dict[str, Any]:
        url = str(
            self.openid_configuration_internal_url or self.openid_configuration_url
        )
        logger.debug("Requesting OIDC config")
        try:
            with urllib.request.urlopen(
                url, timeout=self.discovery_timeout
            ) as response:
                if response.status != 200:
                    raise OidcFetchError(
                        f"Request for OIDC config failed with status {response.status}"
                    )
                config = json.load(response)
        except OidcFetchError:
            raise
        except urllib.error.HTTPError as e:
            raise OidcFetchError(
                f"Request for OIDC config failed with status {e.code}"
            ) from e
        except (OSError, ValueError) as e:
            # URLError, timeouts and invalid JSON
            raise OidcFetchError(
                f"Request for OIDC config failed: {type(e).__name__}"
            ) from e

        if not isinstance(config, dict) or not config.get("jwks_uri"):
            raise OidcFetchError("OIDC config has no jwks_uri")
        return config

    def discover(self) -> Dict[str, Any]:
        """Fetch the OIDC discovery document (once) and set up the JWKS client.

        Raises OidcFetchError when the document can't be fetched or is invalid.
        """
        with self._discovery_lock:
            if self.openid_configuration is not None:
                return self.openid_configuration

            config = self._fetch_openid_configuration()
            issuer = self.issuer or config.get("issuer")
            if not issuer and "iss" in self.required_claims:
                raise OidcFetchError(
                    "OIDC config has no issuer; set `issuer` or remove 'iss' from "
                    "`required_claims`"
                )
            self.issuer = issuer
            self.jwks_client = jwt.PyJWKClient(config["jwks_uri"])
            self.openid_configuration = config
            return config

    @staticmethod
    def create_auth_token_dependency(
        auth_scheme: SecurityBase,
        jwks_client: jwt.PyJWKClient,
        allowed_jwt_audiences: Optional[Sequence[str]],
        *,
        issuer: Optional[str] = None,
        required_claims: Sequence[str] = (),
        auto_error: bool = True,
    ):
        """
        Create a dependency that validates JWT tokens & scopes.

        With `auto_error=False` (and an `auth_scheme` created with
        `auto_error=False`), a request without an Authorization header yields None.
        """

        def get_validator() -> Callable[[str], Dict[str, Any]]:
            def validate(token: str) -> Dict[str, Any]:
                return _decode(
                    token, jwks_client, allowed_jwt_audiences, issuer, required_claims
                )

            return validate

        if auto_error:

            def auth_token(
                auth_header: Annotated[str, Security(auth_scheme)],
                required_scopes: security.SecurityScopes,
            ):
                payload = _validate_header(auth_header, required_scopes, get_validator)
                if payload is None:
                    raise _unauthorized("Not authenticated")
                return payload

            return auth_token

        def optional_auth_token(
            required_scopes: security.SecurityScopes,
            auth_header: Annotated[Optional[str], Security(auth_scheme)] = None,
        ):
            return _validate_header(auth_header, required_scopes, get_validator)

        return optional_auth_token

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
