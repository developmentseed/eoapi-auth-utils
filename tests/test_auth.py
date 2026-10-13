import logging
import time
import urllib.request
from unittest.mock import patch

import jwt
import pytest
from fastapi import FastAPI, HTTPException, status, testclient
from fastapi.security import SecurityScopes
from jwcrypto.jwt import JWK

from eoapi.auth_utils import OidcFetchError, OpenIdConnectAuth


@pytest.fixture
def auth(oidc) -> OpenIdConnectAuth:
    return OpenIdConnectAuth(openid_configuration_url=oidc.discovery_url)


@pytest.fixture
def test_app():
    app = FastAPI()

    @app.get("/test-route")
    def test():
        return {"message": "Hello World"}

    return app


@pytest.fixture
def test_client(test_app):
    return testclient.TestClient(test_app)


def no_scopes() -> SecurityScopes:
    return SecurityScopes([])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


###############################################################################
# Initialization & discovery


def test_oidc_auth_initialization(oidc, auth):
    """
    Auth object is initialized with the correct dependencies.
    """
    assert auth.jwks_client is not None
    assert auth.auth_scheme is not None
    assert auth.valid_token_dependency is not None
    assert oidc.discovery_requests == 1


def test_openid_configuration_is_kept(oidc, auth):
    assert auth.openid_configuration == oidc.config
    assert auth.openid_configuration["token_endpoint"] == oidc.token_endpoint
    assert auth.issuer == oidc.issuer


def test_internal_url_is_fetched(oidc):
    auth = OpenIdConnectAuth(
        openid_configuration_url="https://public.example.com/.well-known/openid-configuration",
        openid_configuration_internal_url=oidc.discovery_url,
    )
    assert auth.openid_configuration == oidc.config
    assert oidc.discovery_requests == 1


def test_discovery_timeout_is_passed(oidc):
    with patch("urllib.request.urlopen", wraps=urllib.request.urlopen) as urlopen:
        OpenIdConnectAuth(
            openid_configuration_url=oidc.discovery_url, discovery_timeout=3.5
        )
    assert urlopen.call_args.kwargs["timeout"] == 3.5


def test_discovery_timeout(oidc):
    oidc.delay = 0.5
    with pytest.raises(OidcFetchError):
        OpenIdConnectAuth(
            openid_configuration_url=oidc.discovery_url, discovery_timeout=0.1
        )


def test_discovery_error_status(oidc):
    oidc.available = False
    with pytest.raises(OidcFetchError, match="500"):
        OpenIdConnectAuth(openid_configuration_url=oidc.discovery_url)


def test_discovery_unreachable():
    with pytest.raises(OidcFetchError):
        OpenIdConnectAuth(
            openid_configuration_url="http://127.0.0.1:9/.well-known/openid-configuration",
            discovery_timeout=1,
        )


def test_discovery_without_issuer(oidc):
    del oidc.config["issuer"]
    with pytest.raises(OidcFetchError, match="issuer"):
        OpenIdConnectAuth(openid_configuration_url=oidc.discovery_url)

    # Explicit issuer, or not requiring `iss`, works.
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url, issuer=oidc.issuer
    )
    assert auth.issuer == oidc.issuer
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url, required_claims=("exp",)
    )
    assert auth.issuer is None


###############################################################################
# Token validation


def test_auth_token_valid(auth, token_builder):
    """
    Auth token dependency returns the token payload when the token is valid.
    """
    token = token_builder({"scope": "test_scope"})

    token_payload = auth.valid_token_dependency(
        auth_header=f"Bearer {token}", required_scopes=no_scopes()
    )
    assert token_payload["scope"] == "test_scope"


def test_auth_token_invalid_audience(auth, token_builder):
    """
    Auth token dependency throws 401 when the token audience is invalid.
    """
    token = token_builder({"scope": "test_scope", "aud": "test_audience"})

    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(
            auth_header=f"Bearer {token}", required_scopes=no_scopes()
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"
    assert isinstance(exc_info.value.__cause__, jwt.exceptions.InvalidAudienceError)


def test_auth_token_allowed_audience(oidc, token_builder):
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url,
        allowed_jwt_audiences=["test_audience"],
    )
    token = token_builder({"aud": "test_audience"})
    payload = auth.valid_token_dependency(
        auth_header=f"Bearer {token}", required_scopes=no_scopes()
    )
    assert payload["aud"] == "test_audience"


def test_auth_token_invalid_signature(auth, token_builder):
    """
    Auth token dependency throws 401 when the token signature is invalid.
    """
    other_key = JWK.generate(
        kty="RSA", size=2048, kid="test", use="sig", e="AQAB", alg="RS256"
    )
    token = token_builder({"scope": "test_scope"}, other_key)

    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(
            auth_header=f"Bearer {token}", required_scopes=no_scopes()
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"
    assert isinstance(exc_info.value.__cause__, jwt.exceptions.InvalidSignatureError)


@pytest.mark.parametrize(
    "claims, error",
    [
        ({"exp": int(time.time()) - 60}, jwt.exceptions.ExpiredSignatureError),
        ({"iss": "https://evil.example.com"}, jwt.exceptions.InvalidIssuerError),
        ({"exp": None}, jwt.exceptions.MissingRequiredClaimError),
        ({"iss": None}, jwt.exceptions.MissingRequiredClaimError),
    ],
)
def test_auth_token_invalid_claims(auth, token_builder, claims, error):
    token = token_builder(claims)
    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(
            auth_header=f"Bearer {token}", required_scopes=no_scopes()
        )
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
    assert isinstance(exc_info.value.__cause__, error)


def test_issuer_override(oidc, token_builder):
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url,
        issuer="https://public.example.com/realms/test",
    )
    ok = token_builder({"iss": "https://public.example.com/realms/test"})
    assert auth.valid_token_dependency(
        auth_header=f"Bearer {ok}", required_scopes=no_scopes()
    )
    with pytest.raises(HTTPException):
        auth.valid_token_dependency(
            auth_header=f"Bearer {token_builder({})}", required_scopes=no_scopes()
        )


def test_required_claims_override(oidc, token_builder):
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url, required_claims=()
    )
    token = token_builder({"exp": None, "iss": None, "sub": "alice"})
    payload = auth.valid_token_dependency(
        auth_header=f"Bearer {token}", required_scopes=no_scopes()
    )
    assert payload == {"sub": "alice"}


@pytest.mark.parametrize(
    "token",
    [
        "foo",
        "Bearer foo",
        "Bearer foo.bar.xyz",
        "Basic foo",
        "Bearer ",
    ],
)
def test_auth_token_invalid_token(auth, token):
    """
    Auth token dependency throws 401 when the token is invalid.
    """
    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(auth_header=token, required_scopes=no_scopes())

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"


def test_tokens_are_not_logged(auth, token_builder, caplog):
    caplog.set_level("DEBUG")
    token = token_builder({"exp": int(time.time()) - 60})
    for header in (f"Bearer {token}", f"Basic {token}"):
        with pytest.raises(HTTPException):
            auth.valid_token_dependency(auth_header=header, required_scopes=no_scopes())
    assert caplog.records
    assert token not in caplog.text


def test_create_auth_token_dependency(auth, token_builder):
    with pytest.raises(TypeError):
        OpenIdConnectAuth.create_auth_token_dependency(  # type: ignore[call-arg]
            auth.auth_scheme, auth.jwks_client, None
        )

    dependency = OpenIdConnectAuth.create_auth_token_dependency(
        auth.auth_scheme, auth.jwks_client, None, issuer=None, required_claims=()
    )
    token = token_builder({"exp": None, "iss": None, "scope": "a"})
    assert dependency(auth_header=f"Bearer {token}", required_scopes=no_scopes())

    strict = OpenIdConnectAuth.create_auth_token_dependency(
        auth.auth_scheme,
        auth.jwks_client,
        None,
        issuer=auth.issuer,
        required_claims=("exp", "iss"),
    )
    with pytest.raises(HTTPException):
        strict(auth_header=f"Bearer {token}", required_scopes=no_scopes())


def test_jwks_outage_is_logged_as_warning(auth, token_builder, caplog):
    dependency = OpenIdConnectAuth.create_auth_token_dependency(
        auth.auth_scheme,
        jwt.PyJWKClient("http://127.0.0.1:1/jwks"),
        None,
        issuer=auth.issuer,
        required_claims=auth.required_claims,
    )
    with caplog.at_level(logging.INFO), pytest.raises(HTTPException) as exc:
        dependency(
            auth_header=f"Bearer {token_builder({})}", required_scopes=no_scopes()
        )
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert [r.levelno for r in caplog.records] == [logging.WARNING]


###############################################################################
# Applying dependencies to routes


def test_apply_auth_dependencies(auth, test_app, test_client):
    for route in test_app.routes:
        auth.apply_auth_dependencies(
            api_route=route, required_token_scopes=["test_scope"]
        )

    resp = test_client.get("/test-route")
    assert resp.json() == {"detail": "Not authenticated"}
    # 403 on FastAPI < 0.116, 401 on later versions
    assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


@pytest.mark.parametrize(
    "required_sent_response",
    [
        ("a", "b", status.HTTP_401_UNAUTHORIZED),
        ("a b c", "a b", status.HTTP_401_UNAUTHORIZED),
        ("a", "ab", status.HTTP_401_UNAUTHORIZED),
        ("a", None, status.HTTP_401_UNAUTHORIZED),
        ("a", "a", status.HTTP_200_OK),
        (None, None, status.HTTP_200_OK),
        (None, "a", status.HTTP_200_OK),
        ("a b c", "d c b a", status.HTTP_200_OK),
    ],
)
def test_reject_wrong_scope(
    auth, test_app, test_client, token_builder, required_sent_response
):
    scope_required, scope_sent, expected_status = required_sent_response
    for route in test_app.routes:
        auth.apply_auth_dependencies(
            api_route=route,
            required_token_scopes=scope_required.split(" ") if scope_required else None,
        )

    token = token_builder({"scope": scope_sent})
    resp = test_client.get("/test-route", headers=bearer(token))
    assert resp.status_code == expected_status
