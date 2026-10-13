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
| `EOAPI_AUTH_CLIENT_ID`, `EOAPI_AUTH_USE_PKCE` | `""`, `true` | Swagger UI Authorization Code Flow |

```py
from eoapi.auth_utils import OpenIdConnectAuth, OpenIdConnectSettings

auth_settings = OpenIdConnectSettings()  # or OpenIdConnectSettings(_env_prefix="AUTH_")
oidc_auth = OpenIdConnectAuth.from_settings(auth_settings)
```

### Integration

In your eoAPI application:

```py
from eoapi.auth_utils import OpenIdConnectAuth, OpenIdConnectSettings
from fastapi import FastAPI
from fastapi.routing import APIRoute
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
    restricted_routes = {
        "/collections": ("POST", "stac:collection:create"),
        "/collections/{collection_id}": ("PUT", "stac:collection:update"),
        "/collections/{collection_id}": ("DELETE", "stac:collection:delete"),
        "/collections/{collection_id}/items": ("POST", "stac:item:create"),
        "/collections/{collection_id}/items/{item_id}": ("PUT", "stac:item:update"),
        "/collections/{collection_id}/items/{item_id}": ("DELETE", "stac:item:delete"),
    }
    api_routes = {
        route.path: route for route in api.app.routes if isinstance(route, APIRoute)
    }
    for endpoint, (method, scope) in restricted_routes.items():
        route = api_routes.get(endpoint)
        if route and method in route.methods:
            oidc_auth.apply_auth_dependencies(route, required_token_scopes=[scope])
```


## Development

### Releases

Releases are managed with [release-please](https://github.com/googleapis/release-please) and use [Conventional Commits](https://www.conventionalcommits.org/):

- `fix: ...` produces a patch release, `feat: ...` a minor release. `chore:`, `docs:`, `test:` etc. don't trigger a release.
- A breaking change (`feat!: ...` or a `BREAKING CHANGE:` footer) produces a minor release while the version is below 1.0.

On every push to `main`, release-please opens or updates a release PR that bumps the version in `eoapi/auth_utils/__init__.py` and updates `CHANGELOG.md`. Merging that PR tags the release and creates the GitHub Release. The package is then published to PyPI ([`publish.yaml`](.github/workflows/publish.yaml)).
