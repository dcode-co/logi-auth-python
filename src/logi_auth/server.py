"""Server-side "Sign in with logi" for Python / Django backends.

Confidential-client OAuth 2.0 code exchange + id_token (RS256) verification.

Why this exists: a backend RP that skips the id_token ``aud`` check can be
tricked into accepting a token minted for a DIFFERENT client (cross-client
account takeover). :meth:`LogiAuthServer.exchange_code_and_verify` ALWAYS
verifies signature + iss + aud + exp + nonce before returning ``sub``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .errors import IdTokenError, ServerError
from .id_token_verifier import verify_id_token


@dataclass
class LogiSession:
    """A verified session. ``sub`` is set only after the id_token checks pass."""

    sub: str
    email: str | None
    id_token: str
    access_token: str
    refresh_token: str | None
    expires_at: int | None
    scope: str | None
    claims: dict


class LogiAuthServer:
    def __init__(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        client_secret: str | None = None,
        issuer: str = "https://api.1pass.dev",
        token_issuer: str = "logi",
        scopes: list[str] | None = None,
        jwks_cache_ttl: int = 3600,
    ):
        if not client_id:
            raise ValueError("client_id is required")
        if not redirect_uri:
            raise ValueError("redirect_uri is required")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_secret = client_secret
        self.issuer = issuer.rstrip("/")
        self.token_issuer = token_issuer
        self.default_scopes = scopes or ["openid", "profile:basic", "email"]
        self.jwks_cache_ttl = jwks_cache_ttl
        self._jwks_cache: dict | None = None
        self._jwks_fetched_at = 0.0

    def authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        scopes: list[str] | None = None,
        code_challenge: str | None = None,
        prompt: str | None = None,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(scopes or self.default_scopes),
            "state": state,
            "nonce": nonce,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        if prompt:
            params["prompt"] = prompt
        return f"{self.issuer}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code_and_verify(
        self, *, code: str, nonce: str, code_verifier: str | None = None
    ) -> LogiSession:
        # The server flow always issued a nonce in authorization_url, so a
        # missing nonce here (e.g. an expired session) is a bug — never proceed
        # with the nonce check silently disabled.
        if not nonce:
            raise ServerError(
                "invalid_nonce", "nonce is required — the sign-in session may have expired"
            )

        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        if code_verifier:
            form["code_verifier"] = code_verifier

        status, body = self._post(f"{self.issuer}/oauth/token", form)
        if not 200 <= status < 300:
            raise ServerError(
                "token_exchange_failed",
                f"Token exchange failed (HTTP {status})",
                detail=body[:2048],
            )

        tokens = self._parse_token_body(body)
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise ServerError(
                "missing_id_token",
                "Token response had no id_token — was `openid` in the scopes?",
            )

        verified = self._verify_with_rotation_retry(id_token, nonce)
        email = verified["claims"].get("email")
        expires_in = tokens.get("expires_in")

        return LogiSession(
            sub=verified["sub"],
            email=email if isinstance(email, str) else None,
            id_token=id_token,
            access_token=tokens.get("access_token"),
            refresh_token=tokens.get("refresh_token"),
            expires_at=(
                int(time.time()) + int(expires_in)
                if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool)
                else None
            ),
            scope=tokens.get("scope"),
            claims=verified["claims"],
        )

    # -- internals -----------------------------------------------------------

    def _verify_with_rotation_retry(self, id_token: str, nonce: str) -> dict:
        expected = {"issuer": self.token_issuer, "client_id": self.client_id, "nonce": nonce}
        jwks, from_cache = self._fetch_jwks(force=False)
        try:
            return verify_id_token(id_token, jwks, expected)
        except IdTokenError as err:
            # Key rotation within the cache TTL — bust + refetch once.
            if err.code == "unknown_kid" and from_cache:
                fresh, _ = self._fetch_jwks(force=True)
                try:
                    return verify_id_token(id_token, fresh, expected)
                except IdTokenError as retry_err:
                    raise self._as_id_token_invalid(retry_err) from retry_err
            raise self._as_id_token_invalid(err) from err

    @staticmethod
    def _as_id_token_invalid(err: IdTokenError) -> ServerError:
        return ServerError(
            "id_token_invalid", f"id_token verification failed ({err.code})", detail=err.code
        )

    def _fetch_jwks(self, force: bool) -> tuple[dict, bool]:
        if (
            not force
            and self._jwks_cache is not None
            and (time.time() - self._jwks_fetched_at) < self.jwks_cache_ttl
        ):
            return self._jwks_cache, True

        status, body = self._get(f"{self.issuer}/.well-known/jwks.json")
        if not 200 <= status < 300:
            raise ServerError("jwks_fetch_failed", f"JWKS fetch failed (HTTP {status})")
        try:
            jwks = json.loads(body)
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                raise ValueError("missing keys")
        except (json.JSONDecodeError, ValueError) as err:
            raise ServerError("jwks_fetch_failed", "JWKS response was malformed", detail=str(err)) from err

        self._jwks_cache = jwks
        self._jwks_fetched_at = time.time()
        return jwks, False

    def _parse_token_body(self, body: str) -> dict:
        try:
            tokens = json.loads(body)
        except json.JSONDecodeError as err:
            raise ServerError(
                "token_exchange_failed", "Token response was not valid JSON", detail=str(err)
            ) from err
        if not isinstance(tokens, dict) or not isinstance(tokens.get("access_token"), str):
            raise ServerError("token_exchange_failed", "Token response was missing access_token")
        return tokens

    def _post(self, url: str, form: dict[str, str]) -> tuple[int, str]:
        data = urllib.parse.urlencode(form).encode()
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        )
        return self._perform(request)

    def _get(self, url: str) -> tuple[int, str]:
        request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        return self._perform(request)

    def _perform(self, request: urllib.request.Request) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:  # noqa: S310 (fixed https scheme)
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            # Non-2xx: return status + body so the caller handles it uniformly.
            return err.code, err.read().decode("utf-8", "replace")
        except urllib.error.URLError as err:
            raise ServerError("network_error", f"Network error: {err.reason}", detail=str(err)) from err
