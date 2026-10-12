# eoAPI Auth Utils

Helpers for authentication & authorization patterns for [eoAPI applications](https://eoapi.dev).

[![PyPI - Version](https://img.shields.io/pypi/v/eoapi.auth-utils)](https://pypi.org/project/eoapi.auth-utils/)

## Usage

### Installation

```
pip install eoapi.auth-utils
# with the token exchange helper
pip install "eoapi.auth-utils[token-exchange]"
```

### Configuration

`OpenIdConnectSettings` reads environment variables (and `.env`) with the `EOAPI_AUTH_` prefix. Pass `_env_prefix` to use another prefix.

| Variable | Default | |
|---|---|---|
| `EOAPI_AUTH_OPENID_CONFIGURATION_URL` | | OIDC discovery URL (public, shown in Swagger UI) |
| `EOAPI_AUTH_OPENID_CONFIGURATION_INTERNAL_URL` | | Discovery URL fetched by the service, if different |
| `EOAPI_AUTH_ALLOWED_JWT_AUDIENCES` | `[]` | JSON list of accepted `aud` values |
| `EOAPI_AUTH_ISSUER` | discovery `issuer` | Expected `iss` claim |
| `EOAPI_AUTH_REQUIRED_CLAIMS` | `["exp", "iss"]` | Claims every token must contain |
| `EOAPI_AUTH_DISCOVERY_TIMEOUT` | `10` | Timeout (seconds) of the discovery request |
| `EOAPI_AUTH_LAZY_DISCOVERY` | `false` | Fetch discovery on first use instead of at startup |
| `EOAPI_AUTH_CLIENT_ID`, `EOAPI_AUTH_USE_PKCE` | `""`, `true` | Swagger UI Authorization Code Flow |

```py
from eoapi.auth_utils import OpenIdConnectAuth, OpenIdConnectSettings

auth_settings = OpenIdConnectSettings()  # or OpenIdConnectSettings(_env_prefix="AUTH_")
oidc_auth = OpenIdConnectAuth.from_settings(auth_settings)
```

The discovery document is kept as `oidc_auth.openid_configuration`, e.g. to read `token_endpoint`.

#### Token validation

Tokens must be RS256-signed by a key of the provider's JWKS. They must contain `exp` and `iss`, and `iss` must match the discovery document's `issuer`. If the service fetches discovery from an internal URL that reports a different issuer, set `issuer` (`EOAPI_AUTH_ISSUER`) to the issuer found in the tokens. To accept tokens without `exp`/`iss` (the behaviour before 0.5.0), set `required_claims=()`.

#### Startup and an unreachable identity provider

By default the discovery document is fetched when `OpenIdConnectAuth` is created, and an `OidcFetchError` is raised if that fails. With `lazy_discovery=True` the app starts regardless. Discovery is attempted on the first request that carries a token. If it fails, such requests get `503` with `Retry-After`, and discovery is retried with exponential backoff (`discovery_backoff`, up to `discovery_max_backoff` seconds). Anonymous requests to optional-auth routes are not affected. Call `oidc_auth.discover()` to fetch it explicitly.

### Protecting routes

`oidc_auth.valid_token_dependency` requires a valid token and returns its claims. Required scopes are given with FastAPI's `Security`. The simplest, and most robust, way is to declare it on the app or on a router:

```py
from fastapi import APIRouter, FastAPI, Security

# Every route of the app
app = FastAPI(dependencies=[Security(oidc_auth.valid_token_dependency)])

# Every route of a router
router = APIRouter(
    dependencies=[Security(oidc_auth.valid_token_dependency, scopes=["stac:item:create"])]
)
```

To restrict only some routes of an existing app (e.g. one built by `stac-fastapi`), use `apply_auth_dependencies_to_app`, mapping paths to methods to required scopes:

```py
from eoapi.auth_utils import OpenIdConnectAuth, OpenIdConnectSettings
from fastapi import FastAPI
from stac_fastapi.api.app import StacApi

auth_settings = OpenIdConnectSettings()

api = StacApi(
    app=FastAPI(
        # ...
        swagger_ui_init_oauth={
            "clientId": auth_settings.client_id,
            "usePkceWithAuthorizationCodeGrant": auth_settings.use_pkce,
        },
    ),
    # ...
)

if auth_settings.openid_configuration_url:
    oidc_auth = OpenIdConnectAuth.from_settings(auth_settings)

    # Implement your custom app-specific auth logic here...
    oidc_auth.apply_auth_dependencies_to_app(
        api.app,
        {
            "/collections": {"POST": ["stac:collection:create"]},
            "/collections/{collection_id}": {
                "PUT": ["stac:collection:update"],
                "DELETE": ["stac:collection:delete"],
            },
            "/collections/{collection_id}/items": {"POST": ["stac:item:create"]},
            "/collections/{collection_id}/items/{item_id}": {
                "PUT": ["stac:item:update"],
                "DELETE": ["stac:item:delete"],
            },
        },
    )
```

A dependency applies to every method of a route. If a route serves several restricted methods, it needs all of their scopes.

> [!WARNING]
> Starting with FastAPI 0.137, routes of routers added with `app.include_router(...)` are resolved lazily and no longer appear in `app.routes`. A loop over `app.routes` then protects nothing. `apply_auth_dependencies_to_app` raises `NoMatchingRoutesError` when no route matches, and logs a warning for each entry without a match (`strict=True` raises instead). For included routers, use app- or router-level `dependencies=[...]` as shown above. `apply_auth_dependencies(route, ...)` still works for individual `APIRoute` objects.

### Optional authentication

For services that allow anonymous access, use `oidc_auth.optional_token_dependency`:

- Without an `Authorization` header it returns `None`.
- With a valid token it returns the token's claims.
- A malformed, invalid or expired token, or a token missing a required scope, still gets `401` with `WWW-Authenticate: Bearer`.

```py
from typing import Any, Dict, Optional

from fastapi import Depends

@app.get("/items")
def items(claims: Optional[Dict[str, Any]] = Depends(oidc_auth.optional_token_dependency)):
    if claims is None:
        ...  # anonymous: public items only
```

### Token exchange (RFC 8693)

A service that calls another protected service on behalf of the user can exchange the user's access token for a token with the downstream audience. This has been tested with Keycloak Standard Token Exchange v2.

```py
from eoapi.auth_utils.token_exchange import TokenExchanger

exchanger = TokenExchanger.from_openid_connect(
    oidc_auth,  # token_endpoint from its discovery document
    client_id="eoapi-raster",
    client_secret=settings.client_secret,  # str or pydantic SecretStr
    audience="data-gateway",
    # token_url="https://...",  # overrides the discovery token_endpoint
    # timeout=5.0, maxsize=1024, expiry_skew=30.0
)

downstream_token = exchanger.exchange(subject_token, subject_exp=claims.get("exp"))
```

- The exchanger sends a `POST` to the token endpoint, with HTTP Basic client authentication and the form fields `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type`/`requested_token_type=urn:ietf:params:oauth:token-type:access_token`, and `audience`.
- Exchanged tokens are cached in memory under the SHA-256 of the subject token, never the token itself. The cache holds at most `maxsize` entries (least recently used are evicted). Each entry expires `expiry_skew` seconds before the earlier of `expires_in` and the subject token's `exp`.
- Concurrent exchanges of the same subject token result in a single request to the IdP.
- Failures raise `TokenExchangeError` (an `HTTPException`). The subject token is never sent downstream as a fallback.

  | Exchange result | Status |
  |---|---|
  | `invalid_grant` / `invalid_token` | 401 |
  | HTTP 403 / `access_denied` | 403 |
  | anything else, a timeout, or a malformed response | 502 |

- Tokens, the client secret and response bodies are never logged.

`exchange()` is blocking. Call it from a sync endpoint or dependency, or with `run_in_threadpool`. Create one exchanger per process and `close()` it on shutdown.


## Development

### Releases

Releases are managed via CICD workflow, as described in the [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/). To create a new release:

1. Update the version in `eoapi/auth_utils/__init__.py` following appropriate [Semantic Versioning convention](https://semver.org/).
1. Push a tagged commit to `main`, with the tag matching the package's new version number.

> [!NOTE]  
> This package makes use of Github's [automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes). These can be later augmented if one sees fit.
