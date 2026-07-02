"""Golden-vector parity test.

tests/fixtures/id-token-vectors.json is a copy of the 4-SDK shared set
(test-vectors/id-token-vectors.json, SoT = generate.mjs). Python MUST produce
identical verify/reject results to Web/iOS/Android/Flutter/Node/Ruby. JWKS is a
fixed snapshot so this runs offline.
"""

import json
import os
import unittest

from logi_auth import IdTokenError, verify_id_token

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "id-token-vectors.json")


class GoldenVectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_FIXTURE, encoding="utf-8") as fh:
            cls.vectors = json.load(fh)
        cls.expected = {
            "issuer": cls.vectors["expected"]["issuer"],
            "client_id": cls.vectors["expected"]["clientId"],
            "nonce": cls.vectors["expected"].get("nonce"),
        }
        cls.jwks = cls.vectors["jwks"]
        cls.now = cls.vectors["now"]

    def test_golden_vectors(self):
        for case in self.vectors["cases"]:
            name = case["name"]
            expect = case["expect"]
            # Cases carrying `accessToken` exercise at_hash binding; cases without
            # it pass access_token=None and skip at_hash (backward compatible).
            access_token = case.get("accessToken")
            with self.subTest(case=name):
                if expect["valid"]:
                    result = verify_id_token(
                        case["token"],
                        self.jwks,
                        self.expected,
                        now=self.now,
                        access_token=access_token,
                    )
                    if expect.get("sub"):
                        self.assertEqual(result["sub"], expect["sub"])
                else:
                    with self.assertRaises(IdTokenError) as ctx:
                        verify_id_token(
                            case["token"],
                            self.jwks,
                            self.expected,
                            now=self.now,
                            access_token=access_token,
                        )
                    if expect.get("error"):
                        self.assertEqual(ctx.exception.code, expect["error"])

    def test_coverage(self):
        # Lock the shared 16-case set (13 base + 3 at_hash) against accidental
        # shrinkage when the fixture is re-synced from the root generator.
        names = {c["name"] for c in self.vectors["cases"]}
        self.assertGreaterEqual(len(self.vectors["cases"]), 16)
        self.assertIn("valid", names)
        self.assertTrue({"at_hash_valid", "at_hash_mismatch", "at_hash_present_no_access_token"} <= names)

    def _case(self, name):
        return next(c for c in self.vectors["cases"] if c["name"] == name)

    def test_jwks_kty_filter_ignores_ec_key_with_same_kid(self):
        # An EC key sharing the RS256 signing kid must be skipped so the correct
        # RSA key is still selected and the token verifies.
        case = self._case("valid")
        rsa_key = self.jwks["keys"][0]
        ec_decoy = {
            "kty": "EC",
            "crv": "P-256",
            "x": "decoy",
            "y": "decoy",
            "kid": rsa_key["kid"],
            "use": "sig",
        }
        mixed_jwks = {"keys": [ec_decoy, rsa_key]}
        result = verify_id_token(case["token"], mixed_jwks, self.expected, now=self.now)
        self.assertEqual(result["sub"], case["expect"]["sub"])

    def test_at_hash_present_without_access_token_is_skipped(self):
        # at_hash in the payload but no access_token supplied -> check skipped.
        case = self._case("at_hash_valid")
        result = verify_id_token(case["token"], self.jwks, self.expected, now=self.now)
        self.assertEqual(result["sub"], case["expect"]["sub"])

    def test_at_hash_mismatch_rejected(self):
        case = self._case("at_hash_valid")
        with self.assertRaises(IdTokenError) as ctx:
            verify_id_token(
                case["token"],
                self.jwks,
                self.expected,
                now=self.now,
                access_token="a-different-access-token",
            )
        self.assertEqual(ctx.exception.code, "at_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
