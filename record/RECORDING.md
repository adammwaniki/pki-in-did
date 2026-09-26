# Recording the demonstration

Five recordings. Each is a script, so a re-shoot is identical.

```bash
record/record.sh all        # all five
record/record.sh part1      # just one
```

Everything needed to record — `asciinema`, `agg`, `ffmpeg` — is in the `recorder` image, so
the host needs nothing installed. Each part produces three files in `recordings/`:

| Extension | Use |
|---|---|
| `.cast` | exact, tiny, replayable, copy-pasteable text (`asciinema play`) |
| `.gif` | drops into slides and READMEs |
| `.mp4` | the video |

Terminal size is fixed at 104×34 (`COLS`/`ROWS`), which is what the reports are laid out for.

## Before recording

```bash
make setup                 # or: scripts/00-reset.sh, if already built
make test                  # nothing should be recorded that does not pass
```

Check `docker compose -p pki-in-did ps` shows six services up and `issuing-ca` healthy.

The narration lines are **inside the scripts** (`narrate "..."`), printed in quotes as they
come up, so what is said and what is run cannot drift apart. Read them aloud; the on-screen
copy is the teleprompter.

## The five parts

### 0 — `part0-setup` (~5 min)

`demo/part0-setup.sh`: `10-offline-root.sh` first, then `00-reset.sh`. The reset deliberately
keeps the root, so on its own it would never show the offline machine — which is the first
thing a viewer needs to see. `10-offline-root.sh` re-run on an existing root reports it and
displays its certificate rather than re-keying it.

Then the whole build, in the order the brief describes: the CSR crossing to the offline
machine and the certificate coming back, the Web-TLS CA, the two issuer certificates with
their different revocation pointers, the walt.id profiles, the DID documents, the CRL, then
OpenID4VCI issuance and the laptop's trust store.

Three things to point at:

- **`--network none` on the offline machine.** `ls -l` on the root key directory, and the
  interface count, which is 1.
- **The certificate profiles**, as the Issuing CA prints them: issuer A has
  `authorityInfoAccess … OCSP … http://mwaniki.dev/ocsp`, issuer B has
  `crlDistributionPoints`. Everything else about them matches.
- **The fingerprint comparison.** The certificate fetched over HTTPS and the one held on the
  offline machine, printed one above the other.

### 1 — `part1-happy-online`

What the specifications give you, and what they do not.

- `did:web:jacarandapropaganda.com` becomes a URL by a textual rule. No registry, no ledger.
- The DID document, with the `x5c` chain **decoded** into subject and issuer lines rather
  than shown as kilobytes of base64.
- The root is **absent** from `x5c`. A chain does not become trustworthy by carrying its own
  root; the verifier already holds it.
- The credential's `kid` and the document's verification method id are the same string.
- Then the fifteen checks, twice: issuer A via OCSP, issuer B via CRL.

Say: *"A conformant DID resolver would stop after check 10. Checks 7 to 9 and 11 to 15 are
verifier policy — that is the gap this demonstration is about."*

### 2 — `part2-happy-offline`

The differentiator. Opens by proving the isolation rather than asserting it: no name
resolves, and `/proc/net/route` has nothing but `lo`.

Then both credentials verify anyway, and the closing scene shows why — the same key published
with `x5u` instead of `x5c`, three outcomes in three lines:

```
with policy refusing x5u, which is the default:   REJECTED   x5u_not_allowed
and with policy allowing it, offline:             REJECTED   x5u_fetch_failed
the same document, allowing x5u, with a network:  ACCEPTED
```

Say: *"`x5c` is a certificate chain. `x5u` is a promise to fetch one. Only one of those
works on a train."*

### 3 — `part3-revocation-online`

The Issuing CA acts alone, twice.

**OCSP.** Revoke with reason `cessationOfOperation`. The script prints the DID document's
hash before and after — *identical*. Verify again: rejected, no republishing anywhere.

Then stop the responder, and show both honest answers: a verifier with a fresh cached
response uses it and says so; a verifier with nothing to fall back on reports `unknown` and
rejects. That distinction is in the brief's own comparison table.

**CRL.** Revoke issuer B and publish nothing. The verifier **accepts — and is right to**.
Hold on that. Then publish, and it rejects. Finally an already-expired CRL, which is
rejected *for being expired* even though it lists the serial, because an expired CRL is not
evidence about anything.

Say: *"Neither DID document was touched. The key is still published. Only the accreditation
was withdrawn."*

### 4 — `part4-revocation-offline` (~5 min; it resets first)

What a disconnected verifier can and cannot know, said plainly.

1. Both credentials verify offline.
2. Revoke issuer A. The laptop, still offline, **still accepts** — it has not been told and
   cannot ask. That is the honest answer, and the reason the response life is a policy
   decision.
3. Ask the same laptop not to rely on anything it cannot confirm: `unknown`, so it rejects.
4. Reconnect once. The rejection then persists offline, because the revoked answer is what
   is now cached.
5. The same arc with a CRL, and finally a cached answer that has expired.

Say: *"Offline, a verifier can be certain, stale, or unsure — and it always says which. What
it never does is treat silence as good news."*

## The closing frame

| | OCSP | CRL |
|---|---|---|
| When a verifier learns | at the next verification, unless a cached response is still fresh | when it next fetches a CRL |
| Network | needed for every check | needed only to fetch a new CRL |
| Work for the authority | a responder that must always answer | a file republished on a schedule |

Three sentences to end on:

1. **The root private key was never on the network.**
2. **The DID documents never changed.**
3. **Only the Issuing CA withdrew the accreditation.**

## Practicalities

- `PAUSE=0` removes the pauses (the recorder sets it). Run a part by hand without it to get
  `[enter to continue]` between scenes for a live audience.
- `BEAT=0` removes the pacing delays as well — useful for a quick check, too fast to watch.
- `NO_COLOR=1` for a plain-text transcript.
- A part that ends early has usually hit a genuine failure; `set -o pipefail` is on
  deliberately. Run it again without `PAUSE=0` to see where.
- Re-shooting part 3 or 4 needs the stack put back first:
  `scripts/90-restore-revocations.sh` (~25 s) rather than a full reset.
