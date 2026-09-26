# Publishing the demonstration on real hostnames

The self-contained stack (`make setup`) needs none of this and is what the recordings show.
This is the public profile: the same demonstration on hostnames that resolve from anywhere,
with real Let's Encrypt certificates, which is what step 10 of the brief asked for.

## What it uses

| Brief | Hostname | Serves | Transport |
|---|---|---|---|
| domain1 | `nrca.labs.adamndegwa.com` | `/nrca.pem` | HTTPS (Let's Encrypt) |
| domain2 | `ca.labs.mwaniki.dev` | `/ocsp`, `/issuing-ca.crl` | **HTTP**, deliberately |
| domain3 | `issuer-a.labs.jacarandapropaganda.com` | `/.well-known/did.json` | HTTPS |
| domain4 | `issuer-b.labs.lawnbull.com` | `/.well-known/did.json` | HTTPS |

All four resolve directly to this server with no proxy in front, so `did:web` resolution and
ACME HTTP-01 both work without DNS credentials or a wildcard certificate.

The DIDs are therefore `did:web:issuer-a.labs.jacarandapropaganda.com` and
`did:web:issuer-b.labs.lawnbull.com`. The bare domains are not used: they are Cloudflare-fronted
and serve unrelated content.

## Two differences from the local profile, both simplifications

1. **No Web-TLS CA.** Caddy presents real publicly-trusted certificates, so the verifier uses
   the system trust store for transport and needs only the National Root CA for credentials.
   The two PKI layers stay just as separate; one of them is simply the real Web PKI now.
2. **No Docker-network DNS aliases.** Resolution goes through real DNS.

Everything else is identical, including the offline capability: `--network none` verification
works exactly as before, because the chain still travels inside `publicKeyJwk`.

## Deploying

The demonstration's own web servers bind `127.0.0.1` only, on ports 8480-8483. Caddy owns 80
and 443 on this host and is left in charge of them.

```bash
# 1. Build the public profile's PKI, DIDs and credentials (about five minutes).
#    This writes to state-public/ and leaves the local profile's state/ untouched.
make public-setup

# 2. Give Caddy the four hostnames. This is the only step that needs root.
sudo cp deploy/caddy/pki-in-did.caddy /etc/caddy/pki-in-did.caddy
sudo sh -c 'grep -q pki-in-did /etc/caddy/Caddyfile || echo "import /etc/caddy/pki-in-did.caddy" >> /etc/caddy/Caddyfile'
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy

# 3. Check it from the outside.
make public-check
```

`make public-check` fetches the root certificate over public HTTPS, compares its fingerprint
with the offline machine's, resolves both DIDs, reads the CRL, queries OCSP, and then verifies
both credentials — online and with `--network none`.

Certificate issuance takes Caddy a few seconds per hostname on first reload. `sudo journalctl
-u caddy -f` shows it.

## Undoing it

```bash
sudo sed -i '/pki-in-did.caddy/d' /etc/caddy/Caddyfile
sudo rm -f /etc/caddy/pki-in-did.caddy
sudo systemctl reload caddy
make public-down
```

Nothing in the local profile is affected at any point.

## Notes for a shared host

- This host already runs Caddy in front of an unrelated multi-container stack. The include
  file adds four site blocks and changes nothing existing; `caddy validate` before reloading
  will say so.
- The demonstration binds no privileged port and no public interface.
- `state-public/offline/` holds the public profile's own National Root CA private key, on the
  same terms as the local one: mounted into a `--network none` container and nowhere else.
- The two profiles have separate roots, so a fingerprint noted from one does not match the
  other. That is correct, and worth saying aloud if both are ever shown.
