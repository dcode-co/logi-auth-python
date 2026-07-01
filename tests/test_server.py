import unittest
from urllib.parse import parse_qs, urlparse

from logi_auth import LogiAuthServer, ServerError


def build():
    return LogiAuthServer(
        client_id="logi_test_client_abc",
        client_secret="secret_xyz",
        redirect_uri="https://rp.example.com/auth/callback",
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

    def test_authorization_url_omits_pkce_when_absent(self):
        url = build().authorization_url(state="st", nonce="no")
        q = parse_qs(urlparse(url).query)
        self.assertNotIn("code_challenge", q)

    def test_requires_client_id_and_redirect_uri(self):
        with self.assertRaises(ValueError):
            LogiAuthServer(client_id="", redirect_uri="x")
        with self.assertRaises(ValueError):
            LogiAuthServer(client_id="x", redirect_uri="")

    def test_exchange_rejects_empty_nonce_before_network(self):
        with self.assertRaises(ServerError) as ctx:
            build().exchange_code_and_verify(code="c", nonce="")
        self.assertEqual(ctx.exception.code, "invalid_nonce")


if __name__ == "__main__":
    unittest.main()
