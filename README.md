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
from stac_fastapi.api.app import StacApi

from .config import ApiSettings

auth_settings = AuthSettings(_env_prefix="AUTH_")
api_settings = ApiSettings()

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
app = api.app

if auth_settings.openid_configuration_url:
    oidc_auth = OpenIdConnectAuth.from_settings(auth_settings)

    # Implement our auth logic...
    restricted_prefixes_methods = {
        "/collections": [
            "POST",
            "PUT",
            "DELETE",
            *([] if api_settings.public_reads else ["GET"]),
        ],
        "/search": [] if api_settings.public_reads else ["POST", "GET"],
    }
    for route in app.routes:
        should_restrict = any(
            route.path.startswith(f"{app.root_path}{prefix}")
            and set(route.methods).intersection(set(restricted_methods))
            for prefix, restricted_methods in restricted_prefixes_methods.items()
        )
        if should_restrict:
            oidc_auth.apply_auth_dependencies(route, required_token_scopes=[])
```


## Development

### Releases

Releases are managed via CICD workflow, as described in the [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/). To create a new release:

1. Update the version in `eoapi/auth_utils/__init__.py` following appropriate [Semantic Versioning convention](https://semver.org/).
1. Push a tagged commit to `main`, with the tag matching the package's new version number.

> [!NOTE]  
> This package makes use of Github's [automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes). These can be later augmented if one sees fit.
