from typing import Dict

import jwt
import pytest
from fastapi import FastAPI, HTTPException, status, testclient
from fastapi.security import SecurityScopes
from jwcrypto.jwt import JWK

from eoapi.auth_utils import OpenIdConnectAuth


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


def bearer(token: str) -> Dict[str, str]:
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
