"""did:web resolution, and the cache that lets it happen with no network.

The Read algorithm: replace `:` with `/`, percent-decode, prepend `https://`, append
`/.well-known/did.json` when there is no path, and GET over TLS.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.parse

from .reasons import (DID_DOCUMENT_ID_MISMATCH, DID_DOCUMENT_MALFORMED,
                      DID_METHOD_UNSUPPORTED, DID_RESOLUTION_FAILED, Rejected)
from .transport import NetworkUnavailable, fetch

PREFIX = "did:web:"


class DidWebError(ValueError):
    """The DID cannot be turned into a URL."""


def did_to_url(did: str) -> str:
    if not did.startswith(PREFIX):
        raise DidWebError(f"not a did:web DID: {did!r}")
    identifier = did[len(PREFIX):]
    if not identifier:
        raise DidWebError("did:web with an empty method-specific identifier")

    segments = [urllib.parse.unquote(s) for s in identifier.split(":")]
    host = segments[0]
    if not host:
        raise DidWebError(f"did:web with an empty host: {did!r}")

    # did:web forbids IP addresses as the method-specific identifier.
    bare_host = host.split(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(bare_host)
    except ValueError:
        pass
    else:
        raise DidWebError(f"did:web must name a domain, not an IP address: {bare_host}")

    if len(segments) == 1:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(segments[1:])}/did.json"


def resolve(did: str, *, transport, store, policy) -> tuple[dict, str, str]:
    """Return (document, source, url). `source` is "network" or "cache".

    The network is authoritative when reachable; the cache is what makes the verifier
    work when it is not. Either way the document is checked again from scratch -- a
    cached document is a copy of evidence, never a stored verdict.
    """
    try:
        url = did_to_url(did)
    except DidWebError as exc:
        raise Rejected(DID_METHOD_UNSUPPORTED, str(exc)) from exc

    network_error = None
    try:
        body = fetch(transport, url, timeout=policy.http_timeout_seconds)
    except NetworkUnavailable as exc:
        network_error = str(exc)
    else:
        document = _parse(body)
        _check_id(document, did)
        store.put_did_document(did, document, url=url)
        return document, "network", url

    cached = store.get_did_document(did)
    if cached is None:
        raise Rejected(
            DID_RESOLUTION_FAILED,
            f"{url} could not be fetched ({network_error}) and nothing is cached for {did}",
        )
    document = cached.document
    _check_id(document, did)
    return document, "cache", url


def _parse(body: bytes) -> dict:
    try:
        document = json.loads(body)
    except (ValueError, TypeError) as exc:
        raise Rejected(DID_DOCUMENT_MALFORMED, f"the DID document is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise Rejected(DID_DOCUMENT_MALFORMED, "the DID document is not a JSON object")
    return document


def _check_id(document: dict, did: str) -> None:
    """did:web Read step 2, and DID Core resolution: the document's id must equal the DID."""
    found = document.get("id")
    if found != did:
        raise Rejected(
            DID_DOCUMENT_ID_MISMATCH,
            f"the document at {did} declares id {found!r}",
        )
