import time
import urllib.request
from typing import Any, Dict, Optional
from unittest.mock import patch

import jwt
import pytest
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Security,
    status,
    testclient,
)
from fastapi.security import SecurityScopes
from jwcrypto.jwt import JWK

from eoapi.auth_utils import NoMatchingRoutesError, OidcFetchError, OpenIdConnectAuth


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
    assert auth.optional_token_dependency is not None
    assert oidc.discovery_requests == 1


def test_openid_configuration_is_kept(oidc, auth):
    assert auth.openid_configuration == oidc.config
    assert auth.openid_configuration["token_endpoint"] == oidc.token_endpoint
    assert auth.issuer == oidc.issuer
    assert auth.discovered


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


def test_create_auth_token_dependency_compat(auth, token_builder):
    """The static factory keeps its positional signature and old defaults."""
    dependency = OpenIdConnectAuth.create_auth_token_dependency(
        auth.auth_scheme, auth.jwks_client, None
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


###############################################################################
# Optional auth


@pytest.fixture
def optional_client(auth):
    app = FastAPI()

    @app.get("/maybe")
    def maybe(
        claims: Optional[Dict[str, Any]] = Depends(auth.optional_token_dependency),
    ):
        return {"sub": claims["sub"] if claims else None}

    @app.get("/maybe-scoped")
    def maybe_scoped(
        claims: Optional[Dict[str, Any]] = Security(
            auth.optional_token_dependency, scopes=["read"]
        ),
    ):
        return {"sub": claims["sub"] if claims else None}

    return testclient.TestClient(app)


def test_optional_no_header(optional_client):
    resp = optional_client.get("/maybe")
    assert resp.status_code == 200
    assert resp.json() == {"sub": None}

    # Scopes only apply to callers that send a token.
    resp = optional_client.get("/maybe-scoped")
    assert resp.status_code == 200


def test_optional_valid_token(optional_client, token_builder):
    resp = optional_client.get("/maybe", headers=bearer(token_builder({"sub": "a"})))
    assert resp.status_code == 200
    assert resp.json() == {"sub": "a"}


def test_optional_direct_call(auth):
    assert (
        auth.optional_token_dependency(required_scopes=no_scopes(), auth_header=None)
        is None
    )


@pytest.mark.parametrize(
    "header",
    [
        "Basic foo",
        "Bearer",
        "Bearer foo.bar.xyz",
        "expired",
        "wrong-issuer",
        "bad-signature",
        "missing-scope",
    ],
)
def test_optional_invalid_token(optional_client, token_builder, header):
    path = "/maybe"
    if header == "expired":
        header = f"Bearer {token_builder({'exp': int(time.time()) - 60})}"
    elif header == "wrong-issuer":
        header = f"Bearer {token_builder({'iss': 'https://evil.example.com'})}"
    elif header == "bad-signature":
        other = JWK.generate(kty="RSA", size=2048, kid="test", alg="RS256")
        header = f"Bearer {token_builder({}, other)}"
    elif header == "missing-scope":
        header = f"Bearer {token_builder({'scope': 'write'})}"
        path = "/maybe-scoped"

    resp = optional_client.get(path, headers={"Authorization": header})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"].startswith("Bearer")


###############################################################################
# Lazy discovery


def test_lazy_discovery_recovers(oidc, token_builder):
    oidc.available = False
    now = [1000.0]
    with patch("eoapi.auth_utils.auth.time.monotonic", lambda: now[0]):
        # The app starts although the IdP is down.
        auth = OpenIdConnectAuth(
            openid_configuration_url=oidc.discovery_url,
            lazy_discovery=True,
            discovery_backoff=2.0,
        )
        assert not auth.discovered
        assert auth.jwks_client is None
        assert oidc.discovery_requests == 0

        app = FastAPI()

        @app.get("/maybe")
        def maybe(claims=Depends(auth.optional_token_dependency)):
            return {"sub": claims["sub"] if claims else None}

        @app.get("/protected", dependencies=[Security(auth.valid_token_dependency)])
        def protected():
            return {}

        client = testclient.TestClient(app)
        headers = bearer(token_builder({"sub": "a"}))

        # Anonymous access doesn't need discovery.
        assert client.get("/maybe").status_code == 200
        assert oidc.discovery_requests == 0

        resp = client.get("/protected", headers=headers)
        assert resp.status_code == 503
        assert resp.headers["Retry-After"] == "2"
        assert oidc.discovery_requests == 1

        # Within the backoff window: no new request to the IdP.
        oidc.available = True
        now[0] += 1
        assert client.get("/maybe", headers=headers).status_code == 503
        assert oidc.discovery_requests == 1

        # After the backoff window: discovery is retried and succeeds.
        now[0] += 1
        resp = client.get("/protected", headers=headers)
        assert resp.status_code == 200
        assert oidc.discovery_requests == 2
        assert client.get("/maybe", headers=headers).json() == {"sub": "a"}
        assert auth.openid_configuration == oidc.config
        assert oidc.discovery_requests == 2


def test_lazy_discovery_backoff_grows(oidc):
    oidc.available = False
    now = [0.0]
    with patch("eoapi.auth_utils.auth.time.monotonic", lambda: now[0]):
        auth = OpenIdConnectAuth(
            openid_configuration_url=oidc.discovery_url,
            lazy_discovery=True,
            discovery_backoff=1.0,
            discovery_max_backoff=4.0,
        )
        retry_after = []
        for _ in range(5):
            with pytest.raises(HTTPException) as exc_info:
                auth._ensure_discovered()
            retry_after.append(exc_info.value.headers["Retry-After"])
            now[0] = auth._next_discovery_attempt
    assert retry_after == ["1", "2", "4", "4", "4"]
    assert oidc.discovery_requests == 5


def test_discover_explicitly(oidc):
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url, lazy_discovery=True
    )
    assert auth.discover() == oidc.config
    assert auth.jwks_client is not None


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


@pytest.fixture
def stac_like_app():
    app = FastAPI()

    @app.get("/collections")
    def list_collections():
        return []

    @app.post("/collections")
    def create_collection():
        return {}

    @app.delete("/collections/{collection_id}")
    def delete_collection(collection_id: str):
        return {}

    return app


def test_apply_auth_dependencies_to_app(auth, stac_like_app, token_builder):
    routes = auth.apply_auth_dependencies_to_app(
        stac_like_app,
        {
            "/collections": {"POST": ["collection:create"]},
            "/collections/{collection_id}": {"DELETE": ["collection:delete"]},
        },
    )
    assert len(routes) == 2

    client = testclient.TestClient(stac_like_app)
    assert client.get("/collections").status_code == 200
    assert client.post("/collections").status_code in (401, 403)
    assert client.delete("/collections/x").status_code in (401, 403)

    create = bearer(token_builder({"scope": "collection:create"}))
    assert client.post("/collections", headers=create).status_code == 200
    assert client.delete("/collections/x", headers=create).status_code == 401


def test_apply_auth_dependencies_to_app_partial(auth, stac_like_app, caplog):
    restricted = {
        "/collections": {"post": ["collection:create"]},
        "/nope": {"GET": None},
    }
    assert len(auth.apply_auth_dependencies_to_app(stac_like_app, restricted)) == 1
    assert "GET /nope" in caplog.text

    with pytest.raises(NoMatchingRoutesError, match="GET /nope"):
        auth.apply_auth_dependencies_to_app(stac_like_app, restricted, strict=True)


@pytest.mark.parametrize(
    "restricted", [{}, {"/nope": {"GET": None}}, {"/collections": {"PUT": None}}]
)
def test_apply_auth_dependencies_to_app_no_match(auth, stac_like_app, restricted):
    with pytest.raises(NoMatchingRoutesError):
        auth.apply_auth_dependencies_to_app(stac_like_app, restricted)
    with pytest.raises(NoMatchingRoutesError):
        auth.apply_auth_dependencies_to_app([], restricted)


def test_apply_auth_dependencies_to_app_included_router(auth):
    """Fails loudly instead of silently protecting nothing when routes are lazy."""
    router = APIRouter()

    @router.post("/collections")
    def create_collection():
        return {}

    app = FastAPI()
    app.include_router(router)

    if any(getattr(r, "path", None) == "/collections" for r in app.routes):
        pytest.skip("FastAPI < 0.137 lists included routes in app.routes")
    with pytest.raises(NoMatchingRoutesError, match="dependencies="):
        auth.apply_auth_dependencies_to_app(app, {"/collections": {"POST": None}})


def test_app_level_dependencies_protect_included_routers(auth, token_builder):
    router = APIRouter()

    @router.get("/collections")
    def collections():
        return []

    app = FastAPI(dependencies=[Security(auth.valid_token_dependency)])
    app.include_router(router, prefix="/api")
    client = testclient.TestClient(app)

    assert client.get("/api/collections").status_code in (401, 403)
    resp = client.get("/api/collections", headers=bearer(token_builder({})))
    assert resp.status_code == 200
