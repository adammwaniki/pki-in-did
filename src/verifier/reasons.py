"""Every reason the verifier can reject, as a stable string.

These strings are the verifier's public contract: the tests assert on them, the demo
scripts print them, and `--json` emits them. Changing one is a breaking change.
"""

# check 1 -- the credential itself
MALFORMED_CREDENTIAL = "malformed_credential"
KEY_REFERENCE_MISSING = "key_reference_missing"
KEY_REFERENCE_NOT_ABSOLUTE = "key_reference_not_absolute"
ISSUER_INCONSISTENT = "issuer_inconsistent"
CREDENTIAL_NOT_YET_VALID = "credential_not_yet_valid"
CREDENTIAL_EXPIRED = "credential_expired"

# check 2 -- algorithm
ALG_NOT_ALLOWED = "alg_not_allowed"

# check 3 -- issuer and key reference agree
KID_ISSUER_MISMATCH = "kid_issuer_mismatch"

# check 4 and 5 -- did:web resolution
DID_METHOD_UNSUPPORTED = "did_method_unsupported"
DID_RESOLUTION_FAILED = "did_resolution_failed"
DID_DOCUMENT_MALFORMED = "did_document_malformed"
DID_DOCUMENT_ID_MISMATCH = "did_document_id_mismatch"

# check 6 -- the DID Core authorization relationship
DID_URL_NOT_ABSOLUTE = "did_url_not_absolute"
VERIFICATION_METHOD_NOT_FOUND = "verification_method_not_found"
NOT_IN_ASSERTION_METHOD = "not_in_assertion_method"
CONTROLLER_MISMATCH = "controller_mismatch"
PUBLIC_KEY_JWK_MISSING = "public_key_jwk_missing"
JWK_CONTAINS_PRIVATE_MATERIAL = "jwk_contains_private_material"
PROOF_PURPOSE_INVALID = "proof_purpose_invalid"

# check 7 and 8 -- the chain is present and identified
X5C_MISSING = "x5c_missing"
X5C_MALFORMED = "x5c_malformed"
X5U_NOT_ALLOWED = "x5u_not_allowed"
X5U_FETCH_FAILED = "x5u_fetch_failed"
X5T_MISMATCH = "x5t_mismatch"

# check 9 -- the binding without which the chain is decorative
SPKI_JWK_MISMATCH = "spki_jwk_mismatch"

# check 10 -- the signature
SIGNATURE_INVALID = "signature_invalid"

# check 11 and 12 -- the profile rules on the leaf
SAN_URI_MISMATCH = "san_uri_mismatch"
KEY_USAGE_MISSING_DIGITAL_SIGNATURE = "key_usage_missing_digital_signature"

# check 13 -- RFC 5280 path validation
NO_TRUST_ANCHORS = "no_trust_anchors"
CHAIN_INCOMPLETE = "chain_incomplete"
CHAIN_UNTRUSTED_ROOT = "chain_untrusted_root"
CHAIN_NAME_MISMATCH = "chain_name_mismatch"
CHAIN_SIGNATURE_INVALID = "chain_signature_invalid"
CHAIN_NOT_A_CA = "chain_not_a_ca"
CHAIN_CA_CANNOT_SIGN_CERTIFICATES = "chain_ca_cannot_sign_certificates"
CHAIN_PATH_LEN_EXCEEDED = "chain_path_len_exceeded"
CHAIN_TOO_LONG = "chain_too_long"
CERTIFICATE_EXPIRED = "certificate_expired"
CERTIFICATE_NOT_YET_VALID = "certificate_not_yet_valid"

# check 14 -- accreditation, not merely certification
ISSUER_NOT_AUTHORIZED_FOR_TYPE = "issuer_not_authorized_for_type"

# check 15 -- revocation
REVOCATION_SOURCE_MISSING = "revocation_source_missing"
REVOCATION_REVOKED = "revocation_revoked"
REVOCATION_UNKNOWN = "revocation_unknown"
REVOCATION_EXPIRED = "revocation_expired"
REVOCATION_STALE = "revocation_stale"
REVOCATION_RESPONSE_UNTRUSTED = "revocation_response_untrusted"
REVOCATION_RESPONSE_MISMATCH = "revocation_response_mismatch"
REVOCATION_RESPONSE_NOT_YET_VALID = "revocation_response_not_yet_valid"
REVOCATION_RESPONSE_NONCE_MISMATCH = "revocation_response_nonce_mismatch"


# the verifier itself failed -- fail closed rather than accept
VERIFIER_ERROR = "verifier_error"


class Rejected(Exception):
    """Raised inside a check to reject with a specific reason."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason
