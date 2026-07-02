"""RS256 id_token verification.

Mirrors the server (server/app/lib/oauth/jwt_verifier.rb) and the other SDKs:
kid -> JWKS -> RS256 signature -> iss / aud / exp / iat / nonce / sub. Passes the
shared 4-SDK golden vectors (../../test-vectors).

Uses the standard ``cryptography`` library for the RSA primitive (Python has no
stdlib RSA verify, just as Dart uses pointycastle). The JWS parsing + claim
checks are implemented here, mirroring verify.ts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import IdTokenError


def verify_id_token(
    id_token: str,
    jwks: dict,
    expected: dict,
    now: int | None = None,
    clock_skew_sec: int = 60,
    access_token: str | None = None,
) -> dict:
    """Verify ``id_token`` and return ``{"sub", "claims"}``.

    Raises :class:`IdTokenError` on any failure — never returns an unverified
    subject. Claim order: signature -> iss -> aud -> exp -> iat -> nonce -> sub
    -> at_hash.

    ``expected`` is ``{"issuer", "client_id", "nonce"}`` (``nonce`` optional).
    ``now`` is Unix seconds; defaults to now. Injectable for deterministic tests.

    ``access_token`` binds the id_token to the access_token per OIDC §3.1.3.6:
    when the payload carries ``at_hash`` **and** ``access_token`` is supplied, the
    left-most 128 bits of ``SHA-256(access_token)`` (base64url, no padding) MUST
    equal ``at_hash``. When either is absent the check is skipped (backward
    compatible with callers that only verify the id_token).
    """
    now = int(time.time()) if now is None else now

    parts = id_token.split(".")
    if len(parts) != 3 or not all(parts):
        raise IdTokenError("malformed")

    header = _decode_json_segment(parts[0])
    payload = _decode_json_segment(parts[1])
    if header is None or payload is None:
        raise IdTokenError("malformed")

    # Only RS256 is accepted — never verify a token whose header declares another
    # (or no) algorithm, even if the RSA signature happens to match.
    if header.get("alg") != "RS256":
        raise IdTokenError("bad_signature")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise IdTokenError("missing_kid")

    # Select the signing key by kid, but only among RSA keys usable for RS256
    # signatures. Filtering on kty/use/alg keeps verification robust if the JWKS
    # later mixes in EC (or encryption) keys: we still pick the correct RSA key
    # instead of tripping over an unrelated one that happens to share a kid.
    jwk = next(
        (
            k
            for k in jwks.get("keys", [])
            if k.get("kid") == kid
            and k.get("kty") == "RSA"
            and k.get("use") in (None, "sig")
            and k.get("alg") in (None, "RS256")
        ),
        None,
    )
    if jwk is None:
        raise IdTokenError("unknown_kid")

    signature = _b64url_decode(parts[2])
    if signature is None or not _verify_rs256(f"{parts[0]}.{parts[1]}".encode(), signature, jwk):
        raise IdTokenError("bad_signature")

    if payload.get("iss") != expected["issuer"]:
        raise IdTokenError("iss_mismatch")

    aud = payload.get("aud")
    if not _audience_matches(aud, expected["client_id"]):
        raise IdTokenError("aud_mismatch")
    # OIDC 3.1.3.7: with multiple audiences an ``azp`` MUST be present; whenever
    # ``azp`` is present it MUST equal our client_id.
    azp = payload.get("azp")
    if isinstance(aud, list) and len(aud) > 1:
        if azp != expected["client_id"]:
            raise IdTokenError("aud_mismatch")
    elif azp is not None:
        if azp != expected["client_id"]:
            raise IdTokenError("aud_mismatch")

    exp = _numeric(payload.get("exp"))
    if exp is None or exp <= now - clock_skew_sec:
        raise IdTokenError("expired")

    iat = _numeric(payload.get("iat"))
    # iat missing or in the future -> malformed (mirrors the other verifiers).
    if iat is None or iat > now + clock_skew_sec:
        raise IdTokenError("malformed")

    expected_nonce = expected.get("nonce")
    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        raise IdTokenError("nonce_mismatch")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise IdTokenError("missing_claim")

    # OIDC 3.1.3.6 at_hash: present-only binding. Checked last, after every other
    # claim has been validated and only when the caller supplies the matching
    # access_token, so id_token-only callers keep their existing behaviour.
    at_hash = payload.get("at_hash")
    if isinstance(at_hash, str) and access_token is not None:
        if _at_hash(access_token) != at_hash:
            raise IdTokenError("at_hash_mismatch")

    return {"sub": sub, "claims": payload}


def _at_hash(access_token: str) -> str:
    # base64url(no padding) of the left-most 128 bits of SHA-256(access_token).
    digest = hashlib.sha256(access_token.encode("utf-8")).digest()[:16]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    n_bytes = _b64url_decode(jwk.get("n", ""))
    e_bytes = _b64url_decode(jwk.get("e", ""))
    if n_bytes is None or e_bytes is None:
        return False
    try:
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(e_bytes, "big"),
            int.from_bytes(n_bytes, "big"),
        ).public_key()
    except (ValueError, TypeError):
        return False
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def _decode_json_segment(segment: str) -> dict | None:
    raw = _b64url_decode(segment)
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _audience_matches(aud: Any, client_id: str) -> bool:
    if isinstance(aud, str):
        return aud == client_id
    if isinstance(aud, list):
        return client_id in aud
    return False


def _numeric(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _b64url_decode(segment: str) -> bytes | None:
    if not isinstance(segment, str):
        return None
    try:
        return base64.urlsafe_b64decode(segment + "=" * ((-len(segment)) % 4))
    except (ValueError, TypeError):
        return None
