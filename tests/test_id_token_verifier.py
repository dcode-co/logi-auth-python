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
            with self.subTest(case=name):
                if expect["valid"]:
                    result = verify_id_token(case["token"], self.jwks, self.expected, now=self.now)
                    if expect.get("sub"):
                        self.assertEqual(result["sub"], expect["sub"])
                else:
                    with self.assertRaises(IdTokenError) as ctx:
                        verify_id_token(case["token"], self.jwks, self.expected, now=self.now)
                    if expect.get("error"):
                        self.assertEqual(ctx.exception.code, expect["error"])

    def test_coverage(self):
        self.assertGreaterEqual(len(self.vectors["cases"]), 9)
        self.assertTrue(any(c["name"] == "valid" for c in self.vectors["cases"]))


if __name__ == "__main__":
    unittest.main()
