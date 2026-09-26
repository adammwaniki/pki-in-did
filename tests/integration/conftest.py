"""Fixtures for the tests that run against the live Docker stack.

Skipped unless PKI_DEMO_STACK=1, so `pytest -m unit` stays hermetic.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

# The test runner mounts the repository at its own absolute host path (see
# scripts/pytest.sh), so these paths are valid both inside the runner and on the host --
# which is what lets the tests hand them to `docker run -v`.
REPO = Path(__file__).resolve().parents[2]
STATE = REPO / "state"
NETWORK = os.environ.get("PKI_DEMO_NETWORK", "pki-in-did_demo")
VERIFIER_IMAGE = os.environ.get("PKI_DEMO_VERIFIER_IMAGE", "pki-in-did/verifier")

NRCA_DOMAIN = "adamndegwa.com"
ISSUING_CA_DOMAIN = "mwaniki.dev"
ISSUER_A_DOMAIN = "jacarandapropaganda.com"
ISSUER_B_DOMAIN = "lawnbull.com"
ISSUER_A_DID = f"did:web:{ISSUER_A_DOMAIN}"
ISSUER_B_DID = f"did:web:{ISSUER_B_DOMAIN}"


def _configured(name: str, fallback: str) -> str:
    """Read a value from config/domains.env, so tests assert what the demo is set to do."""
    try:
        for line in (REPO / "config" / "domains.env").read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip('"')
    except OSError:
        pass
    return fallback


#: The CRL reason the demonstration uses. `privilegeWithdrawn` would be semantically better
#: but `openssl ca` cannot express it -- see record/NOTES-waltid.md.
REVOCATION_REASON = _configured("REVOCATION_REASON", "cessationOfOperation")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("PKI_DEMO_STACK") == "1":
        return
    skip = pytest.mark.skip(reason="live stack not requested; set PKI_DEMO_STACK=1")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


# ------------------------------------------------------------------------ runners

def as_current_user() -> list[str]:
    """`docker run` flags that write files as the invoking user, not as root."""
    return ["-u", f"{os.getuid()}:{os.getgid()}"]


def run(*args: str, check: bool = True, timeout: int = 180, **kw) -> subprocess.CompletedProcess:
    done = subprocess.run(list(args), capture_output=True, text=True, cwd=REPO,
                          timeout=timeout, **kw)
    if check and done.returncode != 0:
        raise AssertionError(
            f"command failed ({done.returncode}): {' '.join(args)}\n"
            f"--- stdout ---\n{done.stdout}\n--- stderr ---\n{done.stderr}"
        )
    return done


def script(name: str, *args: str, check: bool = True, timeout: int = 1800
           ) -> subprocess.CompletedProcess:
    """Run one of the demonstration's scripts.

    The default timeout is generous because these orchestrate containers: a full
    00-reset.sh reissues every key and credential and restarts two JVM services, which
    takes minutes. `run`'s shorter default is for single commands.
    """
    return run("bash", str(REPO / "scripts" / name), *args, check=check, timeout=timeout)


def curl_in_network(*curl_args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Reach a demo domain from inside the demo network, trusting the demo TLS root."""
    return run(
        "docker", "run", "--rm", "--network", NETWORK,
        "-v", f"{STATE}/laptop/trust:/trust:ro",
        "--entrypoint", "curl", VERIFIER_IMAGE,
        "--silent", "--show-error", "--fail",
        "--cacert", "/trust/webtls-root.pem", *curl_args,
        check=check,
    )


def verifier(*args: str, offline: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    network = "none" if offline else NETWORK
    cmd = [
        "docker", "run", "--rm", "--network", network,
        "-v", f"{STATE}/laptop:/laptop",
        "-v", f"{STATE}/credentials:/credentials:ro",
        VERIFIER_IMAGE, "verify",
    ]
    if offline:
        cmd.append("--offline")
    return run(*cmd, *args, check=check)


def verify_json(
    credential: str,
    *,
    offline: bool = False,
    no_cached_revocation: bool = False,
    policy: str | None = None,
) -> dict:
    extra: list[str] = []
    if no_cached_revocation:
        extra.append("--no-cached-revocation")
    if policy:
        extra += ["--policy", policy]
    done = verifier("--json", "--credential", f"/credentials/{credential}", *extra,
                    offline=offline)
    assert done.stdout.strip(), f"verifier printed nothing\n{done.stderr}"
    return json.loads(done.stdout)


# ----------------------------------------------------------------------- fixtures

def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


@pytest.fixture
def state() -> Path:
    assert STATE.exists(), "state/ is missing -- run `make setup` first"
    return STATE


@pytest.fixture
def root_cert(state) -> x509.Certificate:
    return load_cert(state / "offline" / "nrca" / "nrca.pem")


@pytest.fixture
def issuing_cert(state) -> x509.Certificate:
    return load_cert(state / "ca" / "issuing-ca.pem")


@pytest.fixture
def issuer_a_cert(state) -> x509.Certificate:
    return load_cert(state / "ca" / "certs" / "issuer-a.pem")


@pytest.fixture
def issuer_b_cert(state) -> x509.Certificate:
    return load_cert(state / "ca" / "certs" / "issuer-b.pem")


@pytest.fixture
def ocsp_signer_cert(state) -> x509.Certificate:
    return load_cert(state / "ca" / "certs" / "ocsp-signer.pem")


@pytest.fixture
def did_document_a(state) -> dict:
    return json.loads((state / "web" / "issuer-a" / ".well-known" / "did.json").read_text())


@pytest.fixture
def did_document_b(state) -> dict:
    return json.loads((state / "web" / "issuer-b" / ".well-known" / "did.json").read_text())
