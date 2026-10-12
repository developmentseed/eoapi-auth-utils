class OidcFetchError(Exception):
    pass


class NoMatchingRoutesError(LookupError):
    """No route matched the routes to protect, so nothing would be protected."""
