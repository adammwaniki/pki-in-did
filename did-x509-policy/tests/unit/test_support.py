"""The supporting pieces: policy loading, the store, the report, and the CLI.

These moved here from the demonstration this package was extracted from, because this is where
the code they test lives.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests import fixtures as fx
from tests.conftest import assert_accepted

pytestmark = pytest.mark.unit

PACKAGE = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------ policy





def test_replace_returns_a_new_policy_and_leaves_the_original_alone(policy):
    relaxed = policy.replace(revocation_required=False)
    assert relaxed.revocation_required is False
    assert policy.revocation_required is True


def test_replace_refuses_an_unknown_setting(policy):
    with pytest.raises(ValueError):
        policy.replace(no_such_setting=True)


def test_comment_keys_in_the_policy_file_are_ignored(policy):
    assert not any(name.startswith("_") for name in policy.as_dict())


# ------------------------------------------------------------------------- store

def test_the_store_round_trips_a_did_document(store, world):
    store.put_did_document(world.issuer_a.did, world.issuer_a.did_document)
    cached = store.get_did_document(world.issuer_a.did)
    assert cached.document == world.issuer_a.did_document
    assert isinstance(cached.fetched_at, dt.datetime)


def test_the_store_keys_a_did_document_safely_on_disk(store, world):
    """A DID contains colons; the cache filename must not depend on path characters."""
    store.put_did_document("did:web:example.gov:agency:health", {"id": "x"})
    assert store.get_did_document("did:web:example.gov:agency:health").document == {"id": "x"}
    files = list((store.root / "cache" / "did").iterdir())
    assert len(files) == 1
    assert ":" not in files[0].name and "/" not in files[0].name


def test_the_store_keys_an_ocsp_response_by_certificate_and_issuer(store, world):
    payload = world.ocsp_good(world.issuer_a)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, payload)
    assert store.get_ocsp(world.issuer_a.cert, world.issuing.cert).der == payload
    assert store.get_ocsp(world.issuer_b.cert, world.issuing.cert) is None


def test_the_store_round_trips_a_crl(store, world):
    payload = world.crl()
    store.put_crl(world.issuing.cert, payload)
    assert store.get_crl(world.issuing.cert).der == payload


def test_the_store_reads_every_trust_anchor_it_is_pointed_at(store, world, policy):
    anchors = store.trust_anchors(policy.trust_anchors)
    assert [a.subject for a in anchors] == [world.root.cert.subject]


def test_the_store_refuses_to_hold_a_private_key(store, world):
    """A laptop store that contains a private key is a bug worth failing loudly on."""
    with pytest.raises(ValueError):
        store.put_trust_anchor_pem(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")


def test_a_fingerprint_is_reported_for_the_trust_anchor(store, world, policy):
    from did_x509_policy import sha256_fingerprint

    anchor = store.trust_anchors(policy.trust_anchors)[0]
    printed = sha256_fingerprint(anchor)
    assert len(printed.split(":")) == 32
    assert printed == sha256_fingerprint(world.root.cert)


# ------------------------------------------------------------------------ report

def test_the_report_renders_one_numbered_line_per_check(verify, world, policy, store, online):
    from did_x509_policy import render_text

    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    text = render_text(result)
    for check in result.checks:
        assert f"{check.number:>2}." in text
        assert check.title in text
    assert "ACCEPTED" in text


def test_the_report_names_the_failing_check_and_stops_there(verify, world, policy, store, offline):
    from did_x509_policy import render_text

    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=offline)
    text = render_text(result)
    assert "REJECTED" in text
    assert "did_resolution_failed" in text


def test_the_json_report_is_machine_readable_and_complete(verify, world, policy, store, online):
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["accepted"] is True
    assert payload["reason"] is None
    assert len(payload["checks"]) == 15
    assert payload["revocation"]["method"] == "ocsp"
    assert payload["credential"]["issuer"] == world.issuer_a.did
    assert payload["credential"]["keyReference"] == world.issuer_a.vm_id


def test_the_report_shows_the_trust_anchor_and_its_fingerprint(verify, world, policy, store, online):
    from did_x509_policy import render_text

    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert fx.NRCA_CN in render_text(result)


# --------------------------------------------------------------------------- CLI

def _run_cli(*args, store_root: Path):
    """Invoke the CLI as a user would: an installed package, a store, nothing else.

    The store carries its own policy.json, which is how a deployment supplies trust anchors
    and accreditation OIDs -- the package ships neither.
    """
    env = {**os.environ, "LAPTOP_STORE": str(store_root)}
    return subprocess.run(
        [sys.executable, "-m", "did_x509_policy.cli", *args],
        capture_output=True, text=True, env=env, cwd=PACKAGE,
    )


@pytest.fixture
def cli_store(seeded_store, policy):
    """A store with a policy beside it, which is how the CLI learns its trust anchors."""
    (seeded_store.root / "policy.json").write_text(policy.to_json(indent=2))
    return seeded_store


def test_the_cli_exits_zero_on_acceptance_and_one_on_rejection(tmp_path, world, cli_store):
    credential = tmp_path / "a.jwt"
    credential.write_text(world.issuer_a.credential_jose)

    ok = _run_cli("verify", "--offline", "--credential", str(credential), store_root=cli_store.root)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "ACCEPTED" in ok.stdout

    # Same anchor, same policy, but nothing cached: offline with no cache cannot decide.
    empty = tmp_path / "empty-laptop"
    (empty / "trust").mkdir(parents=True)
    (empty / "trust" / "nrca.pem").write_bytes(world.root_pem)
    (empty / "policy.json").write_text((cli_store.root / "policy.json").read_text())
    bad = _run_cli("verify", "--offline", "--credential", str(credential), store_root=empty)
    assert bad.returncode == 1
    assert "REJECTED" in bad.stdout


def test_the_cli_emits_json_on_request(tmp_path, world, cli_store):
    credential = tmp_path / "a.jwt"
    credential.write_text(world.issuer_a.credential_jose)
    done = _run_cli("verify", "--offline", "--json", "--credential", str(credential),
                    store_root=cli_store.root)
    assert done.returncode == 0, done.stdout + done.stderr
    assert json.loads(done.stdout)["accepted"] is True


def test_the_cli_reads_a_credential_from_stdin(tmp_path, world, cli_store):
    env = {**os.environ, "LAPTOP_STORE": str(cli_store.root)}
    done = subprocess.run(
        [sys.executable, "-m", "did_x509_policy.cli", "verify", "--offline", "--json", "--credential", "-"],
        input=world.issuer_a.credential_jose, capture_output=True, text=True, env=env, cwd=PACKAGE,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert json.loads(done.stdout)["accepted"] is True


def test_the_cli_can_print_the_trust_anchor_fingerprint(cli_store):
    done = _run_cli("fingerprint", store_root=cli_store.root)
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(done.stdout.strip().split(":")) >= 32


def test_the_cli_refuses_an_unreadable_credential(tmp_path, cli_store):
    done = _run_cli("verify", "--offline", "--credential", str(tmp_path / "missing.jwt"),
                    store_root=cli_store.root)
    assert done.returncode == 2
    assert "missing.jwt" in done.stderr


# ------------------------------------------------------------------ failing closed

def test_an_unexpected_error_inside_a_check_rejects_rather_than_accepts(
    verify, world, policy, store, online, monkeypatch
):
    """A verifier that crashes has not accepted anything."""
    import did_x509_policy.revocation as revmod

    def explode(*args, **kwargs):
        raise RuntimeError("the responder returned something we never anticipated")

    monkeypatch.setattr(revmod, "check", explode)
    result = verify(world.issuer_a.credential_jose, policy=policy, store=store, transport=online)
    assert result.accepted is False
    assert result.reason == "verifier_error"
    assert "never anticipated" in result.failed_check.detail


def test_the_cli_reports_a_rejection_rather_than_a_traceback(tmp_path, world, cli_store):
    """Nothing in the demonstration should ever show a stack trace."""
    credential = tmp_path / "broken.jwt"
    credential.write_text("this is not a credential at all")
    done = _run_cli("verify", "--offline", "--credential", str(credential),
                    store_root=cli_store.root)
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert "REJECTED" in done.stdout
    assert "malformed_credential" in done.stdout


# --------------------------------------------- handing the laptop a document directly

def test_the_cli_can_cache_a_did_document_without_resolving_it(tmp_path, world, store):
    """Used to show an x5u reference failing where x5c succeeds.

    A disconnected laptop cannot fetch a document, so the demonstration hands it one.
    """
    import json as _json

    document = tmp_path / "did.x5u.json"
    x5u_jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment,
                               x5u=fx.CHAIN_URL_A)
    document.write_text(_json.dumps(fx.build_did_document(
        world.issuer_a.did, jwk=x5u_jwk, fragment=world.issuer_a.fragment)))

    done = _run_cli("cache-document", "--did", world.issuer_a.did, "--file", str(document),
                    store_root=store.root)
    assert done.returncode == 0, done.stdout + done.stderr

    cached = store.get_did_document(world.issuer_a.did)
    assert cached is not None
    assert "x5u" in cached.document["verificationMethod"][0]["publicKeyJwk"]
    assert "x5c" not in cached.document["verificationMethod"][0]["publicKeyJwk"]


def test_caching_an_unreadable_document_fails_cleanly(tmp_path, store):
    done = _run_cli("cache-document", "--did", "did:web:example.gov",
                    "--file", str(tmp_path / "missing.json"), store_root=store.root)
    assert done.returncode == 2
    assert "missing.json" in done.stderr


def test_allow_x5u_is_off_unless_asked_for(tmp_path, world, store):
    """The flag exists so the demonstration can show what x5u costs, not as a default."""
    import json as _json

    document = tmp_path / "did.x5u.json"
    x5u_jwk = fx.ec_public_jwk(world.issuer_a.key, kid=world.issuer_a.fragment,
                               x5u=fx.CHAIN_URL_A)
    document.write_text(_json.dumps(fx.build_did_document(
        world.issuer_a.did, jwk=x5u_jwk, fragment=world.issuer_a.fragment)))
    _run_cli("cache-document", "--did", world.issuer_a.did, "--file", str(document),
             store_root=store.root)
    store.put_ocsp(world.issuer_a.cert, world.issuing.cert, world.ocsp_good(world.issuer_a))

    credential = tmp_path / "a.jwt"
    credential.write_text(world.issuer_a.credential_jose)

    default = _run_cli("verify", "--offline", "--json", "--credential", str(credential),
                       store_root=store.root)
    assert json.loads(default.stdout)["reason"] == "x5u_not_allowed"

    permitted = _run_cli("verify", "--offline", "--allow-x5u", "--json",
                         "--credential", str(credential), store_root=store.root)
    assert json.loads(permitted.stdout)["reason"] == "x5u_fetch_failed"


