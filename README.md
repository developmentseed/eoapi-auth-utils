# eoAPI Auth Utils

Helpers for authentication & authorization patterns for [eoAPI applications](https://eoapi.dev).

[![PyPI - Version](https://img.shields.io/pypi/v/eoapi.auth-utils)](https://pypi.org/project/eoapi.auth-utils/)

## Development

### Releases

Releases are managed via CICD workflow, as described in the [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/). To create a new release:

1. Update the version in `eoapi/auth_utils/__init__.py` following appropriate [Semantic Versioning convention](https://semver.org/).
1. Push a tagged commit to `main`, with the tag matching the package's new version number.

> [!NOTE]  
> This package makes use of Github's [automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes). These can be later augmented if one sees fit.
