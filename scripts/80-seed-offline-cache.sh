#!/usr/bin/env bash
# Prime the laptop's cache while online, so it can decide later with no network.
#
# Brief, alternative procedure step 2: keep the root certificate, the DID documents, an OCSP
# response and the CRLs on the laptop for use without a network. That is exactly what one
# online verification of each credential leaves behind.
#
# To show a cached answer going stale, verify with config/verifier-policy-strict.json
# instead: it narrows the freshness window rather than changing what is cached.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Prime the offline cache from the live stack"

for which in a b; do
  step "Online verification of issuer ${which^^}'s credential, to fill the cache"
  report=$(laptop verify --json --credential "/credentials/issuer-$which-vc-jose.jwt" || true)
  reason=$(printf '%s' "$report" | jq -r '.reason // "none"')
  case "$reason" in
    none)
      ok "accepted; the DID document and the revocation answer are now cached" ;;
    revocation_revoked)
      # A revoked certificate is a legitimate outcome, and the revoked answer is what gets
      # cached. Refusing to continue here would make it impossible to prime a laptop after
      # a revocation, which is exactly what part 4 of the demonstration needs.
      warn "issuer ${which^^} is revoked; the revoked answer is what has been cached" ;;
    *)
      printf '%s' "$report" | jq -r '.checks[] | select(.status == "fail")
              | "      check \(.number) \(.key): \(.detail)"'
      die "issuer ${which^^} failed for a reason unrelated to revocation ($reason); the stack is broken" ;;
  esac
done

step "What the laptop now holds"
find "$STATE/laptop" -type f | sed "s|$STATE/laptop|      laptop|" | sort

ok "this laptop can now decide with no network at all"
