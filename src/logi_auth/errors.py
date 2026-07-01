"""Error types for logi_auth."""


class LogiAuthError(Exception):
    """Base for all errors raised by this package."""


class IdTokenError(LogiAuthError):
    """id_token verification failure.

    ``code`` mirrors the Web verifier and the golden-vector strings exactly
    (e.g. ``"bad_signature"``, ``"aud_mismatch"``).
    """

    CODES = (
        "malformed",
        "missing_kid",
        "unknown_kid",
        "bad_signature",
        "iss_mismatch",
        "aud_mismatch",
        "expired",
        "nonce_mismatch",
        "missing_claim",
    )

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"id_token verification failed: {code}")


class ServerError(LogiAuthError):
    """OAuth / transport failure raised by :class:`LogiAuthServer`."""

    def __init__(self, code: str, message: str, detail=None):
        self.code = code
        self.detail = detail
        super().__init__(message)
