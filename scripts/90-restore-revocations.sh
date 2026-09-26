#!/usr/bin/env bash
# Return every certificate to "valid" without reissuing anything.
#
# The revocation demonstrations need the stack put back between runs, and a full reset
# (scripts/00-reset.sh) regenerates every key and credential -- several minutes. Nothing
# about a revocation requires that: the certificates are unchanged, only their status moved.
# This restores the status, republishes a clean CRL, and reprimes the laptop's cache.
#
# The full reset still exists, and tests/integration/test_reproducibility.py exercises it.
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

step "Mark every certificate valid again in the Issuing CA's database"

python3 - "$STATE/ca/index.txt" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
rows, restored = [], 0
for line in path.read_text().splitlines():
    if not line.strip():
        continue
    fields = line.split("\t")
    if fields[0] == "R":
        fields[0] = "V"
        fields[2] = ""          # the revocation date
        restored += 1
    rows.append("\t".join(fields))
path.write_text("\n".join(rows) + "\n")
print(f"      {restored} certificate(s) returned to valid")
PY

run rm -f "$STATE/ca/revocations.json"

"$REPO/scripts/50-publish-crl.sh" >/dev/null
ok "a clean CRL is published"

step "Reprime the laptop's cache"
run rm -rf "$STATE/laptop/cache"
mkdir -p "$STATE/laptop/cache"/{did,ocsp,crl}
# Put the laptop's policies back, in case a scene swapped in a narrower one.
run cp "$CONFIG/verifier-policy.json" "$STATE/laptop/policy.json"
run cp "$CONFIG/verifier-policy-strict.json" "$STATE/laptop/policy-strict.json"

"$REPO/scripts/80-seed-offline-cache.sh" >/dev/null \
  || die "the credentials do not verify after restoring; run scripts/00-reset.sh"

ok "every certificate is valid again, and the laptop's cache reflects it"
