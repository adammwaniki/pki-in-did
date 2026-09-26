"""An HTTP service around the policy layer.

One endpoint does the work:

    POST /verify   {"credential": "<compact JWS or a VC object>"}
                -> 200 with the full report when accepted
                -> 422 with the full report when rejected

The report is the same object the library returns, so a caller gets every check, not a
boolean. A rejection is 422 rather than 200-with-a-flag because a rejection is the answer to
a request that was well-formed but did not pass -- and because monitoring should see it.

Configuration is environment only, so the image needs no files mounted to be useful:

    DID_X509_TRUST_ANCHOR_PEM     PEM of one or more trust anchors, inline
    DID_X509_TRUST_ANCHOR_FILE    ...or a path to read them from
    DID_X509_POLICY_FILE          a policy JSON file; the shipped default is used otherwise
    DID_X509_POLICY_<SETTING>     override one setting, e.g. DID_X509_POLICY_CLOCK_SKEW_SECONDS
    DID_X509_CACHE_DIR            use a FileStore here instead of an in-memory cache
    DID_X509_TLS_BUNDLE           CA bundle for TLS when resolving did:web
    DID_X509_OFFLINE              "1" to forbid the network entirely

Written against Starlette so the image stays small; it runs under any ASGI server.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from . import __version__
from .policy import Policy
from .store import FileStore, MemoryStore, load_pem_certificates, sha256_fingerprint
from .transport import HttpTransport, OfflineTransport
from .verify import CHECKS, verify


class Configuration:
    """Everything the service needs, read once at startup and reported at /healthz."""

    def __init__(self, env: dict | None = None):
        env = env if env is not None else os.environ
        self.offline = env.get("DID_X509_OFFLINE", "").strip().lower() in ("1", "true", "yes")
        self.tls_bundle = env.get("DID_X509_TLS_BUNDLE") or None
        self.cache_dir = env.get("DID_X509_CACHE_DIR") or None

        policy_file = env.get("DID_X509_POLICY_FILE")
        self.policy = (Policy.from_file(policy_file) if policy_file
                       else Policy.from_env(env=env))

        self.anchors = self._read_anchors(env)
        if self.cache_dir:
            # A FileStore finds anchors through Policy.trust_anchors, relative to its root.
            self.store_factory = lambda: FileStore(self.cache_dir)
        else:
            anchors = self.anchors
            self.store_factory = lambda: MemoryStore(anchors)

    @staticmethod
    def _read_anchors(env) -> list:
        inline = env.get("DID_X509_TRUST_ANCHOR_PEM")
        if inline:
            return load_pem_certificates(inline.encode() if isinstance(inline, str) else inline)
        path = env.get("DID_X509_TRUST_ANCHOR_FILE")
        if path and Path(path).exists():
            return load_pem_certificates(Path(path).read_bytes())
        return []

    def transport(self):
        if self.offline:
            return OfflineTransport()
        return HttpTransport(tls_bundle=self.tls_bundle,
                             timeout=self.policy.http_timeout_seconds)

    def describe(self) -> dict:
        return {
            "version": __version__,
            "offline": self.offline,
            "cache": "file" if self.cache_dir else "memory",
            "trustAnchors": [
                {"subject": a.subject.rfc4514_string(), "fingerprintSha256": sha256_fingerprint(a)}
                for a in self.anchors
            ],
            "checks": [{"number": i + 1, "key": key, "title": title}
                       for i, (key, title) in enumerate(CHECKS)],
        }


def _configuration(request: Request) -> Configuration:
    return request.app.state.configuration


async def healthz(request: Request) -> JSONResponse:
    """Readiness, and a statement of what this verifier will and will not accept.

    A verifier with no trust anchor is not ready: it can only reject, which is safe but
    useless, and a deployment should find that out here rather than from its first rejection.
    """
    configuration = _configuration(request)
    described = configuration.describe()
    ready = bool(described["trustAnchors"])
    return JSONResponse(
        {"status": "ok" if ready else "no trust anchors configured", **described},
        status_code=200 if ready else 503,
    )


async def policy_endpoint(request: Request) -> JSONResponse:
    """The policy in force. Worth being able to read back before trusting a verdict."""
    return JSONResponse(_configuration(request).policy.as_dict())


async def verify_endpoint(request: Request) -> JSONResponse:
    configuration = _configuration(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 -- any malformed body is the same answer
        return JSONResponse({"error": "the request body must be JSON"}, status_code=400)

    credential = body.get("credential") if isinstance(body, dict) else None
    if credential in (None, ""):
        return JSONResponse(
            {"error": "supply the credential as a string or object in `credential`"},
            status_code=400,
        )

    policy = configuration.policy
    overrides = body.get("policy") if isinstance(body, dict) else None
    if isinstance(overrides, dict):
        # A caller may tighten or relax for one request; useful for staged rollout of a rule.
        try:
            policy = policy.replace(**overrides)
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": f"policy override rejected: {exc}"}, status_code=400)

    at = None
    if isinstance(body, dict) and body.get("at"):
        try:
            at = dt.datetime.fromisoformat(str(body["at"]).replace("Z", "+00:00"))
        except ValueError:
            return JSONResponse({"error": "`at` must be an ISO 8601 instant"}, status_code=400)

    result = verify(credential, policy=policy, store=configuration.store_factory(),
                    transport=configuration.transport(), at=at)
    return JSONResponse(result.to_dict(), status_code=200 if result.accepted else 422)


async def root(request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        f"did-x509-policy {__version__}\n\n"
        "POST /verify   {\"credential\": \"...\"}   the fifteen checks\n"
        "GET  /policy                             the policy in force\n"
        "GET  /healthz                            readiness and trust anchors\n"
    )


def create_app(configuration: Configuration | None = None) -> Starlette:
    app = Starlette(routes=[
        Route("/", root, methods=["GET"]),
        Route("/verify", verify_endpoint, methods=["POST"]),
        Route("/policy", policy_endpoint, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
    ])
    app.state.configuration = configuration or Configuration()
    return app


# Served with `uvicorn did_x509_policy.api:create_app --factory`, so that configuration is
# read when the server starts rather than when this module is imported -- which is what lets
# the tests construct an app with their own environment.
