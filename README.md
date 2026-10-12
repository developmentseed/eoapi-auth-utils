# eoAPI Auth Utils

Helpers for authentication & authorization patterns for [eoAPI applications](https://eoapi.dev).

[![PyPI - Version](https://img.shields.io/pypi/v/eoapi.auth-utils)](https://pypi.org/project/eoapi.auth-utils/)

## Usage

### Installation

```
pip install eoapi.auth-utils
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

Tokens must be RS256-signed by a key of the provider's JWKS. They must contain `exp` and `iss`, and `iss` must match the discovery document's `issuer`. If the service fetches discovery from an internal URL that reports a different issuer, set `issuer` (`EOAPI_AUTH_ISSUER`) to the issuer found in the tokens. To accept tokens without `exp`/`iss` (the previous behaviour), set `required_claims=()`.

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


## Development

### Releases

Releases are managed with [release-please](https://github.com/googleapis/release-please) and use [Conventional Commits](https://www.conventionalcommits.org/):

- `fix: ...` produces a patch release, `feat: ...` a minor release. `chore:`, `docs:`, `test:` etc. don't trigger a release.
- A breaking change (`feat!: ...` or a `BREAKING CHANGE:` footer) produces a minor release while the version is below 1.0.

On every push to `main`, release-please opens or updates a release PR that bumps the version in `eoapi/auth_utils/__init__.py` and updates `CHANGELOG.md`. Merging that PR tags the release and creates the GitHub Release. The package is then published to PyPI ([`publish.yaml`](.github/workflows/publish.yaml)).
