"""OAuth 2.0 Token Exchange (RFC 8693).

For services that call another protected service on behalf of a user: the
caller's access token (the subject token) is exchanged at the IdP for a token
whose audience is the downstream service. On failure an error is raised; the
subject token is never used instead.

Exchanged tokens are cached in memory per subject token. The cache key is a hash
of the subject token, never the token itself.

Never log tokens, the client secret, or IdP response bodies.

Requires `httpx` (`pip install "eoapi.auth-utils[token-exchange]"`).
"""

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union

from fastapi import HTTPException, status
from pydantic import SecretStr

from .auth import BEARER_CHALLENGE

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from .auth import OpenIdConnectAuth

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# Exchanged tokens are dropped this many seconds before they expire.
EXPIRY_SKEW = 30.0


class TokenExchangeError(HTTPException):
    """Token exchange failed; carries the status returned to the client."""


def _unauthorized() -> TokenExchangeError:
    return TokenExchangeError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token exchange rejected the access token",
        headers=BEARER_CHALLENGE,
    )


def _forbidden() -> TokenExchangeError:
    return TokenExchangeError(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Token exchange denied",
    )


def _bad_gateway() -> TokenExchangeError:
    return TokenExchangeError(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Token exchange failed",
    )


def token_hash(token: str) -> str:
    """Cache key for a subject token."""
    return hashlib.sha256(token.encode()).hexdigest()


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


@dataclass(frozen=True)
class _Entry:
    token: str
    expires_at: float  # on the exchanger's clock


class TokenExchanger:
    """Exchange subject tokens for downstream tokens, with an in-memory cache."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: Union[str, SecretStr],
        audience: str,
        timeout: float = 5.0,
        maxsize: int = 1024,
        expiry_skew: float = EXPIRY_SKEW,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        """Create the exchanger (one per process)."""
        if httpx is None:  # pragma: no cover
            raise ImportError(
                "TokenExchanger requires httpx: "
                'pip install "eoapi.auth-utils[token-exchange]"'
            )
        if isinstance(client_secret, SecretStr):
            client_secret = client_secret.get_secret_value()
        self.token_url = token_url
        self.client_id = client_id
        self.audience = audience
        self.maxsize = maxsize
        self.expiry_skew = expiry_skew
        self._auth = httpx.BasicAuth(client_id, client_secret)
        self._client = httpx.Client(timeout=timeout)
        self._clock = clock
        self._wall_clock = wall_clock
        self._cache: "OrderedDict[str, _Entry]" = OrderedDict()
        self._lock = threading.Lock()
        # key -> [lock, number of waiters]
        self._inflight: Dict[str, List[Any]] = {}

    @classmethod
    def from_openid_connect(
        cls,
        auth: "OpenIdConnectAuth",
        client_id: str,
        client_secret: Union[str, SecretStr],
        audience: str,
        token_url: Optional[str] = None,
        **kwargs: Any,
    ) -> "TokenExchanger":
        """Create the exchanger, using `token_endpoint` from the discovery document
        of `auth` unless `token_url` is given."""
        if not token_url:
            config = auth.openid_configuration
            if config is None and not auth.lazy_discovery:
                config = auth.discover()
            elif config is None:
                raise ValueError(
                    "OIDC discovery has not completed yet; pass token_url or call "
                    "auth.discover() first"
                )
            token_url = config.get("token_endpoint")
        if not token_url:
            raise ValueError(
                "No token endpoint: pass token_url or use a discovery document with "
                "token_endpoint"
            )
        return cls(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience,
            **kwargs,
        )

    def __repr__(self) -> str:
        """No secrets."""
        return (
            f"TokenExchanger(token_url={self.token_url!r}, "
            f"client_id={self.client_id!r}, audience={self.audience!r})"
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "TokenExchanger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _cached(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= self._clock():
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry.token

    def exchange(self, subject_token: str, subject_exp: Optional[float] = None) -> str:
        """Return a downstream token for `subject_token` or raise TokenExchangeError.

        `subject_exp` (the subject token's `exp` claim) caps the cache lifetime.
        """
        key = token_hash(subject_token)
        token = self._cached(key)
        if token is not None:
            return token

        # Single flight per subject token: concurrent requests wait for one exchange.
        with self._lock:
            slot = self._inflight.setdefault(key, [threading.Lock(), 0])
            slot[1] += 1
        try:
            with slot[0]:
                token = self._cached(key)
                if token is not None:
                    return token
                token, expires_in = self._request(subject_token)
                self._store(key, token, expires_in, subject_exp)
                return token
        finally:
            with self._lock:
                slot[1] -= 1
                if slot[1] == 0:
                    del self._inflight[key]

    def _store(
        self,
        key: str,
        token: str,
        expires_in: Optional[float],
        subject_exp: Optional[float],
    ) -> None:
        lifetimes = []
        if expires_in is not None:
            lifetimes.append(expires_in)
        subject_exp = _number(subject_exp)
        if subject_exp is not None:
            lifetimes.append(subject_exp - self._wall_clock())
        if not lifetimes:
            return
        ttl = min(lifetimes) - self.expiry_skew
        if ttl <= 0:
            return
        with self._lock:
            self._cache[key] = _Entry(token=token, expires_at=self._clock() + ttl)
            self._cache.move_to_end(key)
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def _request(self, subject_token: str) -> Tuple[str, Optional[float]]:
        data = {
            "grant_type": GRANT_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": self.audience,
        }
        try:
            resp = self._client.post(self.token_url, data=data, auth=self._auth)
        except httpx.HTTPError as e:
            # Exception class only: messages may contain request details.
            logger.warning("Token exchange request failed: %s", type(e).__name__)
            raise _bad_gateway() from None

        try:
            body = resp.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}

        if resp.status_code != 200:
            error = body.get("error")
            error = error if isinstance(error, str) else None
            logger.warning(
                "Token exchange rejected: status=%s error=%s", resp.status_code, error
            )
            if resp.status_code == 403 or error == "access_denied":
                raise _forbidden()
            if error in ("invalid_grant", "invalid_token"):
                raise _unauthorized()
            raise _bad_gateway()

        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            logger.warning("Token exchange response has no access_token")
            raise _bad_gateway()

        return token, _number(body.get("expires_in"))
