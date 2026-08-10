import json
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

from logi_auth import IdTokenError, LogiAuthServer, ServerError


def build():
    return LogiAuthServer(
        client_id="logi_test_client_abc",
        client_secret="secret_xyz",
        redirect_uri="https://rp.example.com/auth/callback",
    )


_TOKEN_BODY = json.dumps(
    {
        "access_token": "the-access-token",
        "id_token": "header.payload.sig",
        "refresh_token": "rt",
        "expires_in": 3600,
        "scope": "openid",
    }
)


class ServerTest(unittest.TestCase):
    def test_authorization_url_includes_nonce_state_pkce(self):
        url = build().authorization_url(state="st", nonce="no", code_challenge="cc")
        parsed = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self.assertEqual(parsed.path, "/oauth/authorize")
        self.assertEqual(q["client_id"], "logi_test_client_abc")
        self.assertEqual(q["redirect_uri"], "https://rp.example.com/auth/callback")
        self.assertEqual(q["state"], "st")
        self.assertEqual(q["nonce"], "no")
        self.assertEqual(q["code_challenge"], "cc")
        self.assertEqual(q["code_challenge_method"], "S256")
        self.assertEqual(q["scope"], "openid profile:basic email")

    def test_authorization_url_requires_code_challenge(self):
        # logi mandates PKCE for confidential clients too, so a URL without a
        # challenge is one the server would always reject. Refuse to build it.
        with self.assertRaises(ValueError):
            build().authorization_url(state="st", nonce="no", code_challenge="")

    def test_exchange_requires_code_verifier_before_network(self):
        with self.assertRaises(ServerError) as ctx:
            build().exchange_code_and_verify(code="c", nonce="n", code_verifier="")
        self.assertEqual(ctx.exception.code, "invalid_code_verifier")

    def test_exchange_always_sends_code_verifier(self):
        server = build()
        server._fetch_jwks = lambda force: ({"keys": []}, False)
        captured = {}

        def fake_post(url, form):
            captured.update(form)
            return (200, _TOKEN_BODY)

        def fake_verify(id_token, jwks, expected, access_token=None):
            return {"sub": "sub-1", "claims": {}}

        server._post = fake_post
        with mock.patch("logi_auth.server.verify_id_token", fake_verify):
            server.exchange_code_and_verify(code="c", nonce="n", code_verifier="v")

        self.assertEqual(captured["code_verifier"], "v")

    def test_requires_client_id_and_redirect_uri(self):
        with self.assertRaises(ValueError):
            LogiAuthServer(client_id="", redirect_uri="x")
        with self.assertRaises(ValueError):
            LogiAuthServer(client_id="x", redirect_uri="")

    def test_exchange_rejects_empty_nonce_before_network(self):
        with self.assertRaises(ServerError) as ctx:
            build().exchange_code_and_verify(code="c", nonce="", code_verifier="v")
        self.assertEqual(ctx.exception.code, "invalid_nonce")

    def test_exchange_threads_access_token_into_verification(self):
        server = build()
        server._post = lambda url, form: (200, _TOKEN_BODY)
        server._fetch_jwks = lambda force: ({"keys": []}, False)
        captured = {}

        def fake_verify(id_token, jwks, expected, access_token=None):
            captured["access_token"] = access_token
            return {"sub": "sub-1", "claims": {"email": "a@b.co"}}

        with mock.patch("logi_auth.server.verify_id_token", fake_verify):
            session = server.exchange_code_and_verify(code="c", nonce="n", code_verifier="v")

        # The parsed access_token must be forwarded so at_hash is actually checked.
        self.assertEqual(captured["access_token"], "the-access-token")
        self.assertEqual(session.sub, "sub-1")

    def test_exchange_rejects_at_hash_mismatch(self):
        server = build()
        server._post = lambda url, form: (200, _TOKEN_BODY)
        server._fetch_jwks = lambda force: ({"keys": []}, False)

        def fake_verify(id_token, jwks, expected, access_token=None):
            raise IdTokenError("at_hash_mismatch")

        with mock.patch("logi_auth.server.verify_id_token", fake_verify):
            with self.assertRaises(ServerError) as ctx:
                server.exchange_code_and_verify(code="c", nonce="n", code_verifier="v")

        # at_hash mismatch surfaces as id_token_invalid before a session is built.
        self.assertEqual(ctx.exception.code, "id_token_invalid")
        self.assertEqual(ctx.exception.detail, "at_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
