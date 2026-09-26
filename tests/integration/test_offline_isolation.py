"""Docker, not our own code, is what proves the offline claim."""

from __future__ import annotations

import pytest

from .conftest import (ISSUER_A_DOMAIN, ISSUING_CA_DOMAIN, NRCA_DOMAIN, STATE,
                       VERIFIER_IMAGE, run, verify_json)

pytestmark = [pytest.mark.integration, pytest.mark.offline]


def _in_isolation(*args: str, check: bool = False):
    return run("docker", "run", "--rm", "--network", "none",
               "-v", f"{STATE}/laptop:/laptop",
               "-v", f"{STATE}/credentials:/credentials:ro",
               "--entrypoint", args[0], VERIFIER_IMAGE, *args[1:],
               check=check, timeout=60)


@pytest.mark.parametrize("domain", [NRCA_DOMAIN, ISSUING_CA_DOMAIN, ISSUER_A_DOMAIN])
def test_no_demo_domain_resolves_inside_the_isolated_container(domain):
    done = _in_isolation("getent", "hosts", domain)
    assert done.returncode != 0, f"{domain} resolved with --network none: {done.stdout}"


@pytest.mark.parametrize("url", [
    f"https://{NRCA_DOMAIN}/nrca.pem",
    f"https://{ISSUER_A_DOMAIN}/.well-known/did.json",
    f"http://{ISSUING_CA_DOMAIN}/issuing-ca.crl",
    f"http://{ISSUING_CA_DOMAIN}/ocsp",
])
def test_no_demo_endpoint_is_reachable_inside_the_isolated_container(url):
    done = _in_isolation("curl", "--silent", "--max-time", "5", url)
    assert done.returncode != 0, f"{url} was reachable with --network none"


def test_the_isolated_container_has_no_route_off_the_loopback_interface():
    done = _in_isolation("cat", "/proc/net/route", check=True)
    routes = [line.split() for line in done.stdout.strip().splitlines()[1:]]
    assert all(r[0] == "lo" for r in routes), f"unexpected routes: {done.stdout}"


def test_verification_still_succeeds_in_that_same_isolation():
    """The point of the whole exercise: no network, and still a decision."""
    for credential in ("issuer-a-vc-jose.jwt", "issuer-b-vc-jose.jwt"):
        result = verify_json(credential, offline=True)
        assert result["accepted"] is True, f"{credential}: {result['reason']}"
        assert result["revocation"]["source"] == "cache"
        assert result["didDocument"]["source"] == "cache"


def test_the_laptop_store_is_the_only_input_it_needs():
    """Everything consulted offline is inside state/laptop."""
    for name in ("trust/nrca.pem", "policy.json"):
        assert (STATE / "laptop" / name).exists(), f"missing {name}"
    assert list((STATE / "laptop" / "cache" / "did").glob("*.json"))
    assert list((STATE / "laptop" / "cache" / "ocsp").glob("*"))
    assert list((STATE / "laptop" / "cache" / "crl").glob("*"))
