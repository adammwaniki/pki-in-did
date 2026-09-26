"""A verifier whose only credential trust anchor is a National Root CA certificate.

It decides on a Verifiable Credential issued by a `did:web` issuer whose signing key is
published as a DID Core verification method carrying an RFC 7517 `x5c` chain, and it does
so with or without a network.

The checks, in order, are listed in `verify.CHECKS`.
"""

__all__ = ["verify", "Policy", "LaptopStore"]


def __getattr__(name):  # keep imports cheap for the CLI's fast paths
    if name == "verify":
        from .verify import verify

        return verify
    if name == "Policy":
        from .policy import Policy

        return Policy
    if name == "LaptopStore":
        from .store import LaptopStore

        return LaptopStore
    raise AttributeError(name)
