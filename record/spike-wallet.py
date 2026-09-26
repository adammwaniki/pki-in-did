"""Minimal OpenID4VCI 1.0 pre-authorized-code holder, for the spike."""
import base64, json, sys, time, urllib.parse, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as au

BASE = "http://127.0.0.1:7105"


def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64ud(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def http(method, url, body=None, headers=None, form=False):
    data = None
    h = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# the holder's own key
hk = ec.generate_private_key(ec.SECP256R1())
hp = hk.public_key().public_numbers()
holder_jwk = {"kty": "EC", "crv": "P-256",
              "x": b64u(hp.x.to_bytes(32, "big")), "y": b64u(hp.y.to_bytes(32, "big"))}
holder_did = "did:jwk:" + b64u(json.dumps(holder_jwk, separators=(",", ":"), sort_keys=True).encode())


def es256(header, payload, key):
    si = f"{b64u(json.dumps(header,separators=(',',':')).encode())}.{b64u(json.dumps(payload,separators=(',',':')).encode())}".encode()
    der = key.sign(si, ec.ECDSA(hashes.SHA256()))
    r, s = au.decode_dss_signature(der)
    return f"{si.decode()}.{b64u(r.to_bytes(32,'big')+s.to_bytes(32,'big'))}"


# 1. offer
st, body = http("POST", f"{BASE}/issuer2/credential-offers",
                {"profileId": "openBadgeCredential", "authMethod": "PRE_AUTHORIZED",
                 "runtimeOverrides": {"credentialData": {"credentialSubject": {"id": holder_did}}}})
print("1. offer:", st)
offer_meta = json.loads(body)
uri = urllib.parse.parse_qs(urllib.parse.urlparse(offer_meta["credentialOffer"]).query)["credential_offer_uri"][0]
uri = uri.replace("http://localhost:7005", BASE)

# 2. retrieve offer
st, body = http("GET", uri)
print("2. offer body:", st, body[:500])
offer = json.loads(body)
grants = offer["grants"]
pre = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
code = pre["pre-authorized_code"]
configs = offer.get("credential_configuration_ids")
print("   configuration_ids:", configs, "| tx_code:", pre.get("tx_code"))

# 3. token
st, body = http("POST", f"{BASE}/openid4vci/token",
                {"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                 "pre-authorized_code": code}, form=True)
print("3. token:", st, body[:400])
tok = json.loads(body)
access = tok["access_token"]

# 4. nonce
st, body = http("POST", f"{BASE}/openid4vci/nonce")
print("4. nonce:", st, body[:200])
nonce = json.loads(body).get("c_nonce") if st == 200 else tok.get("c_nonce")

# 5. credential
proof = es256(
    {"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": holder_did + "#0"},
    {"aud": "http://localhost:7005/openid4vci", "iat": int(time.time()), "nonce": nonce},
    hk,
)
st, body = http("POST", f"{BASE}/openid4vci/credential",
                {"credential_configuration_id": configs[0],
                 "proofs": {"jwt": [proof]}},
                headers={"Authorization": f"Bearer {access}"})
print("5. credential:", st, body[:600])
if st == 200:
    open("credential-response.json", "w").write(body)
