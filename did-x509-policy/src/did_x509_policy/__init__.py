"""did-x509-policy — the PKI policy layer a conformant DID verifier leaves to you.

`did:web` resolution ends at a JWK. DID Core says nothing about validating the X.509 chain
that RFC 7517 lets you carry beside it in `x5c`, and a conformant verifier treats that chain
as opaque metadata. So a credential whose chain is *genuine but certifies a different key* is
accepted by a standards-compliant verifier, and must be rejected by something else.

This is that something else. It takes a Verifiable Credential and answers one question:

    does the key that signed this chain up to an authority I trust, and is it still allowed to?

It is not a credential verifier and does not replace one. Run it alongside whatever performs
your OpenID4VP exchange and signature checks.

Library use:

    from did_x509_policy import MemoryStore, Policy, verify, HttpTransport

    store = MemoryStore.from_pem(open("national-root.pem", "rb").read())
    policy = Policy.default().replace(require_issuer_authorization=False)
    result = verify(credential, policy=policy, store=store, transport=HttpTransport())

    if not result.accepted:
        print(result.reason, result.failed_check.detail)

Everything about *where* data comes from is pluggable: implement `Store` for any cache and
`Transport` for any network, or use `OfflineTransport` for no network at all.
"""

from .policy import Policy
from .reasons import Rejected
from .report import render_text
from .store import (CachedBytes, CachedDocument, FileStore, MemoryStore, NullStore, Store,
                    load_pem_certificates, sha256_fingerprint)
from .transport import HttpTransport, NetworkUnavailable, OfflineTransport, Transport
from .verify import CHECKS, Check, Result, verify

__all__ = [
    "verify", "Result", "Check", "CHECKS",
    "Policy", "Rejected", "render_text",
    "Store", "MemoryStore", "FileStore", "NullStore",
    "CachedDocument", "CachedBytes",
    "Transport", "HttpTransport", "OfflineTransport", "NetworkUnavailable",
    "load_pem_certificates", "sha256_fingerprint",
    "__version__",
]

#: Kept in step with the image tag the workflow publishes.
__version__ = "1.0.0"
