"""OAuth 2.0 Token Exchange (RFC 8693)."""

import base64
import json
import threading
import time
from typing import Any, Dict, List, Union
from urllib.parse import parse_qs

import pytest
from pydantic import SecretStr
from werkzeug import Request, Response

from eoapi.auth_utils import OpenIdConnectAuth
from eoapi.auth_utils.token_exchange import (
    ACCESS_TOKEN_TYPE,
    EXPIRY_SKEW,
    GRANT_TYPE,
    TokenExchangeError,
    TokenExchanger,
    token_hash,
)

CLIENT_ID = "eoapi-raster"
SECRET = "s3cr3t-client-secret-value"
SUBJECT = "subject-token-aud-eoapi"
EXCHANGED = "exchanged-token-aud-downstream"
AUDIENCE = "downstream"


class TokenEndpoint:
    """Programmable RFC 8693 token endpoint recording each request."""

    def __init__(self, httpserver):
        self.httpserver = httpserver
        self.requests: List[Dict[str, Any]] = []
        self.status = 200
        self.body: Union[Dict[str, Any], str] = {
            "access_token": EXCHANGED,
            "expires_in": 300,
        }
        self.delay = 0.0
        httpserver.expect_request("/token", method="POST").respond_with_handler(
            self._handle
        )

    @property
    def url(self) -> str:
        return self.httpserver.url_for("/token")

    def _handle(self, request: Request) -> Response:
        self.requests.append(
            {
                "form": {
                    k: v[0] for k, v in parse_qs(request.get_data(as_text=True)).items()
                },
                "authorization": request.headers.get("Authorization"),
                "content_type": request.headers.get("Content-Type"),
            }
        )
        if self.delay:
            time.sleep(self.delay)
        body = self.body
        if isinstance(body, dict) and body.get("access_token") == "{n}":
            body = {**body, "access_token": f"exchanged-{len(self.requests)}"}
        return Response(
            body if isinstance(body, str) else json.dumps(body),
            status=self.status,
            content_type="application/json",
        )


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def endpoint(httpserver) -> TokenEndpoint:
    return TokenEndpoint(httpserver)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def exchanger(endpoint, clock):
    with TokenExchanger(
        token_url=endpoint.url,
        client_id=CLIENT_ID,
        client_secret=SecretStr(SECRET),
        audience=AUDIENCE,
        timeout=1.0,
        clock=clock,
        wall_clock=clock,
    ) as exchanger:
        yield exchanger


###############################################################################
# Request


def test_request(exchanger, endpoint):
    assert exchanger.exchange(SUBJECT) == EXCHANGED

    [request] = endpoint.requests
    assert request["form"] == {
        "grant_type": GRANT_TYPE,
        "subject_token": SUBJECT,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": ACCESS_TOKEN_TYPE,
        "audience": AUDIENCE,
    }
    assert GRANT_TYPE == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert ACCESS_TOKEN_TYPE == "urn:ietf:params:oauth:token-type:access_token"
    basic = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
    assert request["authorization"] == f"Basic {basic}"
    assert request["content_type"] == "application/x-www-form-urlencoded"


def test_plain_string_secret(endpoint):
    with TokenExchanger(endpoint.url, CLIENT_ID, SECRET, AUDIENCE) as exchanger:
        exchanger.exchange(SUBJECT)
    basic = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
    assert endpoint.requests[0]["authorization"] == f"Basic {basic}"


def test_repr_has_no_secret(exchanger):
    assert SECRET not in repr(exchanger)
    assert CLIENT_ID in repr(exchanger)


###############################################################################
# Cache


def test_cache_hit(exchanger, endpoint):
    endpoint.body = {"access_token": "{n}", "expires_in": 300}
    assert exchanger.exchange(SUBJECT) == "exchanged-1"
    assert exchanger.exchange(SUBJECT) == "exchanged-1"
    assert exchanger.exchange("other-subject") == "exchanged-2"
    assert len(endpoint.requests) == 2


def test_cache_key_is_hash(exchanger):
    exchanger.exchange(SUBJECT)
    assert list(exchanger._cache) == [token_hash(SUBJECT)]
    assert token_hash(SUBJECT) != SUBJECT
    assert all(SUBJECT not in key for key in exchanger._cache)


def test_cache_expires_with_expires_in(exchanger, endpoint, clock):
    endpoint.body = {"access_token": "{n}", "expires_in": 300}
    assert exchanger.exchange(SUBJECT) == "exchanged-1"
    clock.now += 300 - EXPIRY_SKEW - 1
    assert exchanger.exchange(SUBJECT) == "exchanged-1"
    clock.now += 1
    assert exchanger.exchange(SUBJECT) == "exchanged-2"


def test_cache_expires_with_subject_exp(exchanger, endpoint, clock):
    endpoint.body = {"access_token": "{n}", "expires_in": 300}
    subject_exp = clock.now + 100  # earlier than expires_in
    assert exchanger.exchange(SUBJECT, subject_exp) == "exchanged-1"
    clock.now += 100 - EXPIRY_SKEW - 1
    assert exchanger.exchange(SUBJECT, subject_exp) == "exchanged-1"
    clock.now += 1
    assert exchanger.exchange(SUBJECT, subject_exp) == "exchanged-2"


@pytest.mark.parametrize(
    "body, subject_exp_in",
    [
        ({"access_token": "{n}", "expires_in": EXPIRY_SKEW}, None),
        ({"access_token": "{n}", "expires_in": 300}, EXPIRY_SKEW - 1),
        # No lifetime known at all
        ({"access_token": "{n}"}, None),
        ({"access_token": "{n}", "expires_in": "300"}, None),
    ],
)
def test_not_cached(exchanger, endpoint, clock, body, subject_exp_in):
    endpoint.body = body
    subject_exp = clock.now + subject_exp_in if subject_exp_in is not None else None
    assert exchanger.exchange(SUBJECT, subject_exp) == "exchanged-1"
    assert exchanger.exchange(SUBJECT, subject_exp) == "exchanged-2"
    assert not exchanger._cache


def test_custom_skew(endpoint, clock):
    endpoint.body = {"access_token": "{n}", "expires_in": 10}
    with TokenExchanger(
        endpoint.url, CLIENT_ID, SECRET, AUDIENCE, expiry_skew=5, clock=clock
    ) as exchanger:
        exchanger.exchange(SUBJECT)
        clock.now += 4
        assert exchanger.exchange(SUBJECT) == "exchanged-1"
        clock.now += 1
        assert exchanger.exchange(SUBJECT) == "exchanged-2"


def test_cache_is_bounded(endpoint, clock):
    endpoint.body = {"access_token": "{n}", "expires_in": 300}
    with TokenExchanger(
        endpoint.url, CLIENT_ID, SECRET, AUDIENCE, maxsize=2, clock=clock
    ) as exchanger:
        exchanger.exchange("s1")  # exchanged-1
        exchanger.exchange("s2")  # exchanged-2
        assert exchanger.exchange("s1") == "exchanged-1"  # s1 most recently used
        exchanger.exchange("s3")  # exchanged-3, evicts s2
        assert len(exchanger._cache) == 2
        assert exchanger.exchange("s1") == "exchanged-1"
        assert exchanger.exchange("s2") == "exchanged-4"
        assert len(endpoint.requests) == 4


###############################################################################
# Concurrency


def test_single_flight(exchanger, endpoint):
    endpoint.body = {"access_token": "{n}", "expires_in": 300}
    endpoint.delay = 0.2
    results: List[str] = []
    barrier = threading.Barrier(8)

    def run():
        barrier.wait()
        results.append(exchanger.exchange(SUBJECT))

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == ["exchanged-1"] * 8
    assert len(endpoint.requests) == 1
    assert exchanger._inflight == {}


def test_single_flight_failure_is_not_shared_forever(exchanger, endpoint):
    endpoint.status = 500
    with pytest.raises(TokenExchangeError):
        exchanger.exchange(SUBJECT)
    endpoint.status = 200
    assert exchanger.exchange(SUBJECT) == EXCHANGED
    assert exchanger._inflight == {}


###############################################################################
# Errors


@pytest.mark.parametrize(
    "status_code, body, expected",
    [
        (400, {"error": "invalid_grant"}, 401),
        (400, {"error": "invalid_token"}, 401),
        (401, {"error": "invalid_token"}, 401),
        (403, {"error": "whatever"}, 403),
        (403, "", 403),
        (400, {"error": "access_denied"}, 403),
        (400, {"error": "invalid_request"}, 502),
        (401, {"error": "invalid_client"}, 502),
        (500, {"error": "server_error"}, 502),
        (503, "<html>down</html>", 502),
        (400, ["invalid_grant"], 502),
        (400, {"error": ["invalid_grant"]}, 502),
        (200, "not json", 502),
        (200, ["access_token"], 502),
        (200, {"token_type": "Bearer"}, 502),
        (200, {"access_token": ""}, 502),
        (200, {"access_token": 42}, 502),
    ],
)
def test_errors(exchanger, endpoint, status_code, body, expected):
    endpoint.status = status_code
    endpoint.body = body if isinstance(body, (dict, str)) else json.dumps(body)
    with pytest.raises(TokenExchangeError) as exc_info:
        exchanger.exchange(SUBJECT)
    assert exc_info.value.status_code == expected
    if expected == 401:
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
    # Failures are not cached.
    assert not exchanger._cache


def test_timeout(endpoint):
    endpoint.delay = 0.5
    with TokenExchanger(
        endpoint.url, CLIENT_ID, SECRET, AUDIENCE, timeout=0.1
    ) as exchanger:
        with pytest.raises(TokenExchangeError) as exc_info:
            exchanger.exchange(SUBJECT)
    assert exc_info.value.status_code == 502


def test_unreachable():
    with TokenExchanger(
        "http://127.0.0.1:9/token", CLIENT_ID, SECRET, AUDIENCE, timeout=1
    ) as exchanger:
        with pytest.raises(TokenExchangeError) as exc_info:
            exchanger.exchange(SUBJECT)
    assert exc_info.value.status_code == 502


@pytest.mark.parametrize(
    "status_code, body",
    [
        (200, {"access_token": EXCHANGED, "expires_in": 300}),
        (400, {"error": "invalid_grant", "error_description": EXCHANGED}),
        (500, f"<html>{SECRET} {SUBJECT} {EXCHANGED}</html>"),
        (200, {"access_token": ""}),
    ],
)
def test_no_secrets_logged(exchanger, endpoint, caplog, status_code, body):
    caplog.set_level("DEBUG")
    endpoint.status = status_code
    endpoint.body = body
    try:
        exchanger.exchange(SUBJECT)
    except TokenExchangeError:
        pass
    logged = caplog.text + "".join(str(r.args) for r in caplog.records)
    for secret in (SUBJECT, SECRET, EXCHANGED, "error_description", "<html>"):
        assert secret not in logged


###############################################################################
# Discovery


def test_token_url_from_discovery(oidc, httpserver):
    auth = OpenIdConnectAuth(openid_configuration_url=oidc.discovery_url)
    exchanger = TokenExchanger.from_openid_connect(
        auth, CLIENT_ID, SECRET, AUDIENCE, timeout=2.0
    )
    assert exchanger.token_url == oidc.token_endpoint
    exchanger.close()

    exchanger = TokenExchanger.from_openid_connect(
        auth, CLIENT_ID, SECRET, AUDIENCE, token_url="https://override/token"
    )
    assert exchanger.token_url == "https://override/token"
    exchanger.close()


def test_token_url_lazy_discovery(oidc):
    auth = OpenIdConnectAuth(
        openid_configuration_url=oidc.discovery_url, lazy_discovery=True
    )
    with pytest.raises(ValueError, match="discovery"):
        TokenExchanger.from_openid_connect(auth, CLIENT_ID, SECRET, AUDIENCE)
    auth.discover()
    exchanger = TokenExchanger.from_openid_connect(auth, CLIENT_ID, SECRET, AUDIENCE)
    assert exchanger.token_url == oidc.token_endpoint
    exchanger.close()


def test_token_url_missing(oidc):
    del oidc.config["token_endpoint"]
    auth = OpenIdConnectAuth(openid_configuration_url=oidc.discovery_url)
    with pytest.raises(ValueError, match="token endpoint"):
        TokenExchanger.from_openid_connect(auth, CLIENT_ID, SECRET, AUDIENCE)
