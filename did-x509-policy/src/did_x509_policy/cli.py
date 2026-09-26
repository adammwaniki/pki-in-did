"""The verifier's command line -- what stands in for "your laptop" in the demonstration.

    verify          decide on a credential, online or with --offline
    fingerprint     print the SHA-256 fingerprint of each trust anchor
    resolve         resolve a did:web DID and print the document
    cache-document  place a DID document in the cache, as though it had been resolved
    inspect         print a credential's header and payload without deciding

The cache fills as a side effect of verifying online, which is what
scripts/80-seed-offline-cache.sh does; there is no separate seeding command.

Exit codes: 0 accepted, 1 rejected, 2 could not run the check at all.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

DEFAULT_STORE = os.environ.get("LAPTOP_STORE", "/laptop")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifier",
        description="Verify a Verifiable Credential against a National Root CA trust anchor.",
    )
    parser.add_argument("--store", default=DEFAULT_STORE,
                        help=f"the laptop store directory (default {DEFAULT_STORE})")
    parser.add_argument("--policy", default=None,
                        help="policy file (default: <store>/policy.json, else the shipped policy)")
    sub = parser.add_subparsers(dest="command")

    def shared(subparser):
        """Accept --store and --policy after the subcommand as well as before it.

        argparse normally requires a parent parser's options to precede the subcommand,
        which is a needless trap for anyone typing `verify --policy ...`. SUPPRESS means
        the subcommand only overrides these when they are actually given.
        """
        subparser.add_argument("--store", default=argparse.SUPPRESS)
        subparser.add_argument("--policy", default=argparse.SUPPRESS)
        return subparser

    v = shared(sub.add_parser("verify", help="decide on a credential"))
    v.add_argument("--credential", "-c", required=True,
                   help="path to the credential, or - to read standard input")
    v.add_argument("--offline", action="store_true",
                   help="use no network at all; decide from the local store only")
    v.add_argument("--json", action="store_true", help="emit the machine-readable report")
    v.add_argument("--no-cached-revocation", action="store_true",
                   help="do not fall back to a cached OCSP response or CRL; a verifier that "
                        "has never seen this certificate before")
    v.add_argument("--no-colour", action="store_true", help="never colour the output")
    v.add_argument("--allow-x5u", action="store_true",
                   help="follow a JWK's x5u reference; off by default because it cannot be "
                        "followed without a network")

    shared(sub.add_parser("fingerprint",
                          help="print each trust anchor's SHA-256 fingerprint"))

    c = shared(sub.add_parser(
        "cache-document",
        help="place a DID document in the local cache, as though it had been resolved"))
    c.add_argument("--did", required=True)
    c.add_argument("--file", required=True)

    r = shared(sub.add_parser("resolve", help="resolve a did:web DID"))
    r.add_argument("did")
    r.add_argument("--offline", action="store_true")

    i = shared(sub.add_parser("inspect", help="print a credential without deciding on it"))
    i.add_argument("--credential", "-c", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    from .policy import DEFAULT_POLICY_PATH, Policy
    from .store import LaptopStore

    store = LaptopStore(args.store)
    policy_path = getattr(args, "policy", None) or store.policy_path() or DEFAULT_POLICY_PATH
    try:
        policy = Policy.from_file(policy_path)
    except (OSError, ValueError) as exc:
        print(f"verifier: cannot read the policy at {policy_path}: {exc}", file=sys.stderr)
        return 2

    if args.command == "cache-document":
        return _cache_document(args, store)
    if args.command == "fingerprint":
        return _fingerprint(store, policy)
    if args.command == "verify":
        return _verify(args, store, policy)
    if args.command == "resolve":
        return _resolve(args, store, policy)
    if args.command == "inspect":
        return _inspect(args)
    return 2


# ------------------------------------------------------------------- commands

def _verify(args, store, policy) -> int:
    from .report import render_text
    from .verify import verify

    try:
        credential = _read_credential(args.credential)
    except OSError as exc:
        print(f"verifier: cannot read {args.credential}: {exc}", file=sys.stderr)
        return 2

    if args.no_cached_revocation:
        policy = policy.replace(allow_cached_revocation=False)
    if args.allow_x5u:
        policy = policy.replace(allow_x5u=True)

    result = verify(credential, policy=policy, store=store,
                    transport=_transport(args.offline, store, policy))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(render_text(result, colour=False if args.no_colour else None))
    return 0 if result.accepted else 1


def _cache_document(args, store) -> int:
    """Put a DID document into the cache without resolving it.

    Used to hand a disconnected laptop a document it could not have fetched -- which is how
    the demonstration shows an x5u reference failing where x5c succeeds.
    """
    try:
        document = json.loads(Path(args.file).read_text())
    except (OSError, ValueError) as exc:
        print(f"verifier: cannot read {args.file}: {exc}", file=sys.stderr)
        return 2
    path = store.put_did_document(args.did, document, url=f"(supplied from {args.file})")
    print(f"cached {args.did} -> {path}")
    return 0


def _fingerprint(store, policy) -> int:
    from .store import sha256_fingerprint

    anchors = store.trust_anchors(policy.trust_anchors)
    if not anchors:
        print(f"verifier: no trust anchor found under {store.root}", file=sys.stderr)
        return 2
    for anchor in anchors:
        print(f"{sha256_fingerprint(anchor)}  {anchor.subject.rfc4514_string()}")
    return 0


def _resolve(args, store, policy) -> int:
    from .didweb import resolve
    from .reasons import Rejected

    try:
        document, source, url = resolve(args.did, transport=_transport(args.offline, store, policy),
                                        store=store, policy=policy)
    except Rejected as exc:
        print(f"verifier: {exc.reason}: {exc.detail}", file=sys.stderr)
        return 1
    print(f"# {args.did} -> {url}  (from {source})", file=sys.stderr)
    print(json.dumps(document, indent=2))
    return 0


def _inspect(args) -> int:
    from .credential import parse

    parsed = parse(_read_credential(args.credential))
    print(json.dumps({
        "form": parsed.form,
        "header": parsed.header,
        "issuer": parsed.issuer,
        "keyReference": parsed.key_reference,
        "types": parsed.types,
        "payload": parsed.payload,
    }, indent=2))
    return 0


# -------------------------------------------------------------------- helpers

def _read_credential(reference: str):
    if reference == "-":
        return sys.stdin.read()
    return Path(reference).read_text()


def _transport(offline: bool, store, policy):
    from .transport import HttpTransport, OfflineTransport

    if offline:
        return OfflineTransport()
    return HttpTransport(tls_bundle=store.tls_bundle(), timeout=policy.http_timeout_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
