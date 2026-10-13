import json
import time
from typing import Any, Optional

import pytest
from jwcrypto.jwt import JWK, JWT
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

DISCOVERY_PATH = "/realms/test/.well-known/openid-configuration"


@pytest.fixture(scope="session")
def test_key() -> "JWK":
    return JWK.generate(
        kty="RSA", size=2048, kid="test", use="sig", e="AQAB", alg="RS256"
    )


class OIDCServer:
    """Local OIDC provider: discovery document and JWKS (pytest-httpserver)."""

    def __init__(self, httpserver: HTTPServer, key: "JWK"):
        self.httpserver = httpserver
        self.key = key
        self.issuer = httpserver.url_for("/realms/test")
        self.discovery_url = httpserver.url_for(DISCOVERY_PATH)
        self.config: dict[str, Any] = {
            "issuer": self.issuer,
            "jwks_uri": httpserver.url_for("/realms/test/jwks"),
        }
        self.discovery_requests = 0
        httpserver.expect_request(DISCOVERY_PATH).respond_with_handler(self._discovery)
        httpserver.expect_request("/realms/test/jwks").respond_with_json(
            {"keys": [key.export_public(as_dict=True)]}
        )

    def _discovery(self, request: Request) -> Response:
        self.discovery_requests += 1
        return Response(json.dumps(self.config), content_type="application/json")

    def token(self, claims: dict[str, Any], key: Optional["JWK"] = None) -> str:
        """Signed RS256 token; `iss` and `exp` default to valid values.

        Pass a claim with value None to leave it out.
        """
        payload = {"iss": self.issuer, "exp": int(time.time()) + 300, **claims}
        payload = {k: v for k, v in payload.items() if v is not None}
        jwt_token = JWT(
            header={k: self.key.get(k) for k in ["alg", "kid"]}, claims=payload
        )
        jwt_token.make_signed_token(key or self.key)
        return jwt_token.serialize()


@pytest.fixture
def oidc(httpserver: HTTPServer, test_key: "JWK") -> OIDCServer:
    return OIDCServer(httpserver, test_key)


@pytest.fixture
def token_builder(oidc: OIDCServer):
    return oidc.token
