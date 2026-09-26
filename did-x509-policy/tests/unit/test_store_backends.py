"""Every supplied backend, and a hostile one, against the same behaviour.

This is what "backend-agnostic" has to mean to be worth saying: the verification logic does not
know which store it has, and a store cannot change a verdict by misbehaving -- only make the
verifier's information worse, which it then reports.

Copy this file when you implement `Store` for Redis, S3 or a database.
"""

from __future__ import annotations

import datetime as dt

import pytest

from did_x509_policy import FileStore, MemoryStore, NullStore, verify
from tests import fixtures as fx
from tests.conftest import DeadTransport, assert_accepted, assert_rejected

pytestmark = pytest.mark.unit


# ------------------------------------------------------------------- the backends

@pytest.fixture
def memory_store(world):
    return MemoryStore([world.root.cert])


@pytest.fixture
def file_store(tmp_path, world):
    root = tmp_path / "kit"
    (root / "trust").mkdir(parents=True)
    (root / "trust" / "nrca.pem").write_bytes(world.root_pem)
    return FileStore(root)


@pytest.fixture
def null_store(world):
    return NullStore([world.root.cert])


class HostileStore:
    """A store that lies: it returns a document for a DID nobody asked about.

    A cache is a copy of evidence, never a stored verdict. If this can change an outcome, the
    design is wrong.
    """

    def __init__(self, anchors, poison: dict):
        self._anchors = list(anchors)
        self._poison = poison

    def trust_anchors(self, refs=()):
        return list(self._anchors)

    def get_did_document(self, did):
        from did_x509_policy.store import CachedDocument

        return CachedDocument(document=self._poison,
                              fetched_at=dt.datetime.now(tz=dt.timezone.utc))

    def put_did_document(self, did, document, *, url=None): return None
    def get_ocsp(self, cert, issuer): return None
    def put_ocsp(self, cert, issuer, der, *, url=None): return None
    def get_crl(self, issuer): return None
    def put_crl(self, issuer, der, *, url=None): return None


# --------------------------------------------------- the same behaviour, every backend

@pytest.mark.parametrize("backend", ["memory_store", "file_store", "null_store"])
def test_a_genuine_credential_is_accepted_online_on_every_backend(
    request, backend, world, policy, online
):
    store = request.getfixturevalue(backend)
    # MemoryStore and NullStore hold their anchors directly; only FileStore reads the path.
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))


@pytest.mark.parametrize("backend", ["memory_store", "file_store", "null_store"])
def test_a_decorative_chain_is_rejected_on_every_backend(
    request, backend, world, policy, online
):
    """The check that matters must not depend on where things are cached."""
    store = request.getfixturevalue(backend)
    impostor = fx.ec_key()
    jwk = fx.ec_public_jwk(impostor, kid=world.issuer_a.fragment,
                           x5c=[world.issuer_a.cert, world.issuing.cert])
    online.serve(world.issuer_a.did_url,
                 fx.build_did_document(world.issuer_a.did, jwk=jwk,
                                       fragment=world.issuer_a.fragment))
    credential = fx.sign_jws_compact(fx.vc_payload(world.issuer_a.did), impostor,
                                     kid=world.issuer_a.vm_id)
    assert_rejected(verify(credential, policy=policy, store=store, transport=online),
                    "spki_jwk_mismatch")


@pytest.mark.parametrize("backend", ["memory_store", "file_store"])
def test_a_caching_backend_can_answer_offline_after_one_online_pass(
    request, backend, world, policy, online
):
    store = request.getfixturevalue(backend)
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))

    offline = verify(world.issuer_a.credential_jose, policy=policy, store=store,
                     transport=DeadTransport())
    assert_accepted(offline)
    assert offline.revocation.source == "cache"
    assert offline.did_document_source == "cache"


def test_the_null_backend_cannot_answer_offline_and_says_so(world, policy, online):
    """Not a defect. Choosing NullStore is choosing freshness over availability."""
    store = NullStore([world.root.cert])
    assert_accepted(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=online))
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=DeadTransport()),
                    "did_resolution_failed")


def test_a_backend_with_no_anchors_rejects_everything(world, policy, online):
    """A verifier nobody has configured must not look like one that trusts nothing by choice."""
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy,
                           store=MemoryStore([]), transport=online),
                    "no_trust_anchors")


def test_a_lying_cache_cannot_turn_a_rejection_into_an_acceptance(world, policy):
    """The hostile store serves a document whose JWK is not the leaf's key."""
    poison = fx.build_did_document(
        world.issuer_a.did,
        jwk=fx.ec_public_jwk(fx.ec_key(), kid=world.issuer_a.fragment,
                             x5c=[world.issuer_a.cert, world.issuing.cert]),
        fragment=world.issuer_a.fragment,
    )
    store = HostileStore([world.root.cert], poison)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=DeadTransport()),
                    "spki_jwk_mismatch")


def test_a_lying_cache_cannot_substitute_another_issuer(world, policy):
    """A document for the wrong DID is caught by the id check, not trusted because it is cached."""
    store = HostileStore([world.root.cert], world.issuer_b.did_document)
    assert_rejected(verify(world.issuer_a.credential_jose, policy=policy, store=store,
                           transport=DeadTransport()),
                    "did_document_id_mismatch")


# --------------------------------------------------------- the contract, mechanically

@pytest.mark.parametrize("backend", ["memory_store", "file_store", "null_store"])
def test_each_backend_satisfies_the_store_protocol(request, backend):
    from did_x509_policy import Store

    assert isinstance(request.getfixturevalue(backend), Store)


def test_the_hostile_store_also_satisfies_the_protocol(world):
    """So the protocol is not doing the work -- the verification logic is."""
    from did_x509_policy import Store

    assert isinstance(HostileStore([world.root.cert], {}), Store)


def test_memory_and_file_backends_round_trip_everything(world, memory_store, file_store):
    for store in (memory_store, file_store):
        store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
        assert store.get_did_document(world.issuer_a.did).document == world.issuer_a.did_document

        response = world.ocsp_good(world.issuer_a)
        store.put_ocsp(world.issuer_a.cert, world.issuing.cert, response)
        assert store.get_ocsp(world.issuer_a.cert, world.issuing.cert).der == response
        assert store.get_ocsp(world.issuer_b.cert, world.issuing.cert) is None

        crl = world.crl()
        store.put_crl(world.issuing.cert, crl)
        assert store.get_crl(world.issuing.cert).der == crl


def test_the_null_backend_forgets_immediately(world, null_store):
    null_store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    assert null_store.get_did_document(world.issuer_a.did) is None


def test_a_file_backend_refuses_to_hold_a_private_key(file_store):
    """A trust store holds certificates. Loudly, so a packaging mistake is caught early."""
    with pytest.raises(ValueError):
        file_store.put_trust_anchor_pem(
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")


def test_a_memory_backend_can_be_built_from_pem(world):
    store = MemoryStore.from_pem(world.root_pem)
    assert [a.subject for a in store.trust_anchors()] == [world.root.cert.subject]


def test_building_a_memory_backend_from_rubbish_fails_immediately(world):
    with pytest.raises(ValueError):
        MemoryStore.from_pem(b"not a certificate")
