"""logi_auth — server-side "Sign in with logi" for Python / Django backends.

Confidential OAuth 2.0 code exchange + id_token (RS256) verification. Same
safety contract as the iOS/Android/Web/Flutter/Node/Ruby SDKs (shared golden
vectors).
"""

from .errors import IdTokenError, LogiAuthError, ServerError
from .id_token_verifier import verify_id_token
from .server import LogiAuthServer, LogiSession

__version__ = "1.0.1"

__all__ = [
    "LogiAuthServer",
    "LogiSession",
    "verify_id_token",
    "LogiAuthError",
    "IdTokenError",
    "ServerError",
    "__version__",
]
