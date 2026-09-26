"""The demonstration's own policy files, checked against the package's schema.

Everything else about the policy layer -- the store backends, the CLI, the report, failing
closed -- is tested in did-x509-policy/tests, where that code lives. This file only asserts
that the two policy files this demonstration ships are valid and say what the brief requires.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

CONFIG = Path(__file__).resolve().parents[2] / "config"


def test_the_shipped_policy_encodes_the_briefs_rules(policy):
    assert policy.trust_anchors == ["trust/nrca.pem"]
    assert policy.revocation_required is True
    assert policy.allowed_algs == ["ES256"]


def test_the_shipped_policy_encodes_the_source_documents_binding_rule(policy):
    assert policy.require_spki_jwk_binding is True
    assert policy.require_san_uri_equals_did is True
    assert policy.require_assertion_method is True


def test_a_missing_chain_is_not_a_configurable_rule(policy):
    """The brief's second rule is a premise, not a setting: with no chain there is nothing
    to validate against the National Root CA."""
    assert "require_x5c" not in policy.as_dict()
    assert policy.allow_x5u is False


def test_selected_freshness_values_match_the_plan(policy):
    assert policy.ocsp_max_age_seconds == 300
    assert policy.crl_max_age_seconds == 3600
    assert policy.clock_skew_seconds == 30


def test_the_strict_policy_is_the_default_policy_only_tighter():
    """The freshness scenes must not quietly relax anything else."""
    from did_x509_policy import Policy

    default = Policy.from_file(CONFIG / "verifier-policy.json")
    strict = Policy.from_file(CONFIG / "verifier-policy-strict.json")

    assert strict.clock_skew_seconds == 0
    assert strict.ocsp_max_age_seconds < default.ocsp_max_age_seconds
    assert strict.crl_max_age_seconds < default.crl_max_age_seconds

    tightened = {"clock_skew_seconds", "ocsp_max_age_seconds", "crl_max_age_seconds"}
    for name, value in default.as_dict().items():
        if name not in tightened:
            assert strict.as_dict()[name] == value, f"{name} differs beyond the freshness knobs"


def test_both_policy_files_are_accepted_by_the_package(policy):
    """A setting the package does not know is a typo, and must fail loudly."""
    from did_x509_policy import Policy

    for name in ("verifier-policy.json", "verifier-policy-strict.json"):
        Policy.from_file(CONFIG / name)


def test_comment_keys_in_the_policy_files_are_ignored(policy):
    assert not any(name.startswith("_") for name in policy.as_dict())
