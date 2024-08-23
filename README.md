# eoAPI Auth Utils

Helpers for authentication & authorization patterns for [eoAPI applications](https://eoapi.dev).

[![PyPI - Version](https://img.shields.io/pypi/v/eoapi.auth-utils)](https://pypi.org/project/eoapi.auth-utils/)

## Usage

### Installation

```
pip install eoapi.auth-utils
```

### Integration

In your eoAPI application:

```py
from eoapi.auth_utils import AuthSettings, OpenIdConnectAuth
from fastapi import FastAPI
from fastapi.routing import APIRoute
from stac_fastapi.api.app import StacApi

auth_settings = AuthSettings(_env_prefix="AUTH_")

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

Releases are managed via CICD workflow, as described in the [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/). To create a new release:

1. Update the version in `eoapi/auth_utils/__init__.py` following appropriate [Semantic Versioning convention](https://semver.org/).
1. Push a tagged commit to `main`, with the tag matching the package's new version number.

> [!NOTE]  
> This package makes use of Github's [automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes). These can be later augmented if one sees fit.
