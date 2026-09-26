"""Shared fixtures.

The verifier's public contract, as these tests exercise it:

    from verifier.policy import Policy
    from verifier.store import LaptopStore
    from verifier.verify import verify

    result = verify(credential, policy=..., store=..., transport=..., at=None)
    result.accepted   -> bool
    result.reason     -> reason code of the first failing check, or None
    result.checks     -> ordered list of Check(number, key, title, status, detail)
    result.revocation -> RevocationOutcome(method, status, source, next_update) or None
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from . import pkifixtures as fx

UTC = dt.timezone.utc


# ------------------------------------------------------------------- transports

class NetworkUnavailable(Exception):
    """Raised by a transport that has no network. Mirrors verifier.transport."""


class FakeTransport:
    """An in-memory network. Routes map an exact URL to bytes or to a callable."""

    def __init__(self, routes: dict[str, object] | None = None):
        self.routes: dict[str, object] = dict(routes or {})
        self.gets: list[str] = []
        self.posts: list[str] = []
        self.offline = False

    # -- wiring helpers used by the tests
    def serve(self, url: str, payload) -> "FakeTransport":
        self.routes[url] = payload
        return self

    def withdraw(self, url: str) -> "FakeTransport":
        self.routes.pop(url, None)
        return self

    def get(self, url: str, *, timeout: float | None = None) -> bytes:
        self.gets.append(url)
        return self._resolve(url, None)

    def post(self, url: str, body: bytes, *, content_type: str, timeout: float | None = None) -> bytes:
        self.posts.append(url)
        return self._resolve(url, body)

    def _resolve(self, url: str, body: bytes | None) -> bytes:
        if url not in self.routes:
            raise NetworkUnavailable(f"no route for {url}")
        payload = self.routes[url]
        if callable(payload):
            payload = payload(body)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode("utf-8")
        return payload


class DeadTransport:
    """No network at all -- what `docker run --network none` looks like from inside."""

    offline = True

    def get(self, url: str, *, timeout: float | None = None) -> bytes:
        raise NetworkUnavailable("no network (offline)")

    def post(self, url: str, body: bytes, *, content_type: str, timeout: float | None = None) -> bytes:
        raise NetworkUnavailable("no network (offline)")


# --------------------------------------------------------------------- fixtures

@pytest.fixture(scope="session")
def world() -> fx.DemoWorld:
    """The synthetic demonstration: root, issuing CA, OCSP signer, issuers A and B.

    Session-scoped: RSA key generation is the slowest thing in the suite. Tests that
    need a variant certificate build just that certificate from these authorities.
    """
    return fx.build_world()


@pytest.fixture
def policy():
    from verifier.policy import Policy

    return Policy.from_file(Path(__file__).resolve().parents[1] / "config" / "verifier-policy.json")


@pytest.fixture
def store(tmp_path, world):
    """A freshly provisioned laptop: the root certificate and nothing else."""
    from verifier.store import LaptopStore

    root = tmp_path / "laptop"
    (root / "trust").mkdir(parents=True)
    (root / "trust" / "nrca.pem").write_bytes(world.root_pem)
    return LaptopStore(root)


@pytest.fixture
def online(world) -> FakeTransport:
    """A transport serving exactly what the live stack serves in the happy path."""
    t = FakeTransport()
    t.serve(f"https://{fx.NRCA_DOMAIN}/nrca.pem", world.root_pem)
    for issuer in (world.issuer_a, world.issuer_b):
        t.serve(issuer.did_url, issuer.did_document)
    # A well-behaved responder echoes the nonce the verifier sent (RFC 6960 §4.4.1).
    t.serve(fx.OCSP_URL,
            lambda body: world.ocsp_good(world.issuer_a, nonce=fx.nonce_of_request(body)))
    t.serve(fx.CRL_URL, world.crl())
    return t


@pytest.fixture
def offline() -> DeadTransport:
    return DeadTransport()


@pytest.fixture
def verify():
    from verifier.verify import verify as _verify

    return _verify


@pytest.fixture
def seeded_store(store, world):
    """A laptop whose cache has been primed while online -- the offline starting point."""
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    store.put_did_document(world.issuer_b.did, world.issuer_b.did_document)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))
    store.put_crl(world.issuing.cert, world.crl())
    return store


# ------------------------------------------------------------------- assertions

def assert_rejected(result, reason: str):
    __tracebackhide__ = True
    assert not result.accepted, (
        f"expected rejection with reason {reason!r} but the credential was accepted\n"
        + _render(result)
    )
    assert result.reason == reason, (
        f"expected reason {reason!r}, got {result.reason!r}\n" + _render(result)
    )


def assert_accepted(result):
    __tracebackhide__ = True
    assert result.accepted, f"expected acceptance, got reason {result.reason!r}\n" + _render(result)


def _render(result) -> str:
    lines = []
    for check in result.checks:
        lines.append(f"  {check.number:>2}. [{check.status:<4}] {check.key}: {check.detail}")
    return "\n".join(lines)
