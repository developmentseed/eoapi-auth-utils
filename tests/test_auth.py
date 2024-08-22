import json
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Security, status, testclient
from jwcrypto.jwt import JWK, JWT

from eoapi.auth_utils import OpenIdConnectAuth


@pytest.fixture
def test_key() -> "JWK":
    return JWK.generate(
        kty="RSA", size=2048, kid="test", use="sig", e="AQAB", alg="RS256"
    )


@pytest.fixture
def public_key(test_key: "JWK") -> Dict[str, Any]:
    return test_key.export_public(as_dict=True)


@pytest.fixture
def private_key(test_key: "JWK") -> Dict[str, Any]:
    return test_key.export_private(as_dict=True)


@pytest.fixture(autouse=True)
def mock_jwks(public_key: "rsa.RSAPrivateKey"):
    mock_oidc_config = {"jwks_uri": "https://example.com/jwks"}

    mock_jwks = {"keys": [public_key]}

    with (
        patch("urllib.request.urlopen") as mock_urlopen,
        patch("jwt.PyJWKClient.fetch_data") as mock_fetch_data,
    ):
        mock_oidc_config_response = MagicMock()
        mock_oidc_config_response.read.return_value = json.dumps(
            mock_oidc_config
        ).encode()
        mock_oidc_config_response.status = 200

        mock_urlopen.return_value.__enter__.return_value = mock_oidc_config_response
        mock_fetch_data.return_value = mock_jwks
        yield mock_urlopen


@pytest.fixture
def token_builder(test_key: "JWK"):
    def build_token(payload: Dict[str, Any], key=None) -> str:
        jwt_token = JWT(
            header={k: test_key.get(k) for k in ["alg", "kid"]},
            claims=payload,
        )
        jwt_token.make_signed_token(key or test_key)
        return jwt_token.serialize()

    return build_token


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


def test_oidc_auth_initialization(mock_jwks: MagicMock):
    """
    Auth object is initialized with the correct dependencies.
    """
    openid_configuration_url = "https://example.com/.well-known/openid-configuration"
    auth = OpenIdConnectAuth(openid_configuration_url=openid_configuration_url)
    assert auth.jwks_client is not None
    assert auth.auth_scheme is not None
    assert auth.valid_token_dependency is not None
    mock_jwks.assert_called_once_with(openid_configuration_url)


def test_auth_token_valid(token_builder):
    """
    Auth token dependency returns the token payload when the token is valid.
    """
    token = token_builder({"scope": "test_scope"})

    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    token_payload = auth.valid_token_dependency(
        auth_header=f"Bearer {token}", required_scopes=Security([])
    )
    assert token_payload["scope"] == "test_scope"


def test_auth_token_invalid_audience(token_builder):
    """
    Auth token dependency throws 401 when the token audience is invalid.
    """
    token = token_builder({"scope": "test_scope", "aud": "test_audience"})

    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(
            auth_header=f"Bearer {token}", required_scopes=Security([])
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"
    assert isinstance(exc_info.value.__cause__, jwt.exceptions.InvalidAudienceError)


def test_auth_token_invalid_signature(token_builder):
    """
    Auth token dependency throws 401 when the token signature is invalid.
    """
    other_key = JWK.generate(
        kty="RSA", size=2048, kid="test", use="sig", e="AQAB", alg="RS256"
    )
    token = token_builder({"scope": "test_scope", "aud": "test_audience"}, other_key)

    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(
            auth_header=f"Bearer {token}", required_scopes=Security([])
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
    ],
)
def test_auth_token_invalid_token(token):
    """
    Auth token dependency throws 401 when the token is invalid.
    """
    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.valid_token_dependency(auth_header=token, required_scopes=Security([]))

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"


def test_apply_auth_dependencies(test_app, test_client):
    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    for route in test_app.routes:
        auth.apply_auth_dependencies(
            api_route=route, required_token_scopes=["test_scope"]
        )

    resp = test_client.get("/test-route")
    assert resp.json() == {"detail": "Not authenticated"}
    assert resp.status_code == status.HTTP_403_FORBIDDEN


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
    test_app, test_client, token_builder, required_sent_response
):
    auth = OpenIdConnectAuth(
        openid_configuration_url="https://example.com/.well-known/openid-configuration"
    )

    scope_required, scope_sent, expected_status = required_sent_response
    for route in test_app.routes:
        auth.apply_auth_dependencies(
            api_route=route,
            required_token_scopes=scope_required.split(" ") if scope_required else None,
        )

    token = token_builder({"scope": scope_sent})
    resp = test_client.get("/test-route", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == expected_status
