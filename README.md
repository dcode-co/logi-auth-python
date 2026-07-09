# logi-auth (Python)

Server-side **"Sign in with logi"** for Python / Django backends — confidential
OAuth 2.0 Authorization Code exchange + **id_token (RS256) verification**. Only
dependency: `cryptography` (no HTTP client dependency — stdlib `urllib`).

This is the **confidential / backend** counterpart to the public-client SDKs
(browser, iOS, Android, Flutter). If your RP has a backend, verify on the
server with this package — do **not** rely on a client-side check.

> **Why it matters:** a backend that skips the id_token `aud` check can be
> tricked into accepting a token minted for a *different* client (cross-client
> account takeover — the launchcrew/krx incident). `exchange_code_and_verify`
> always verifies signature + iss + aud + exp + nonce before returning `sub`.

## Supported versions

| Requirement | Version |
|-------------|---------|
| **Python** | **>= 3.9** |
| **Django** | any — the package is framework-agnostic; use it from any view |
| Flask / FastAPI / etc. | any |
| Dependencies | `cryptography >= 41.0` |

## Install

```bash
pip install logi-auth
```

## Django view example

```python
# settings.py (or a dedicated logi_auth.py config module)
import os
from logi_auth import LogiAuthServer

LOGI = LogiAuthServer(
    client_id=os.environ["LOGI_CLIENT_ID"],
    client_secret=os.environ["LOGI_CLIENT_SECRET"],  # confidential client
    redirect_uri="https://app.example.com/auth/logi/callback",
)
```

```python
# views.py
import secrets

from django.http import HttpResponseBadRequest
from django.shortcuts import redirect

from logi_auth import ServerError

from .settings import LOGI
from .models import User


def logi_start(request):
    state = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    request.session["logi_state"] = state
    request.session["logi_nonce"] = nonce
    return redirect(LOGI.authorization_url(state=state, nonce=nonce))


def logi_callback(request):
    if request.GET.get("state") != request.session.pop("logi_state", None):
        return HttpResponseBadRequest("state mismatch")

    # The provider may redirect back with ?error=access_denied (user cancelled)
    # and no `code` — handle that before the exchange instead of 500-ing.
    if request.GET.get("error"):
        return redirect(f"/login?error={request.GET['error']}")
    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("missing authorization code")

    try:
        result = LOGI.exchange_code_and_verify(
            code=code,
            nonce=request.session.pop("logi_nonce", None),
        )
    except ServerError as e:
        # result.sub is only ever set after signature+iss+aud+exp+nonce all pass.
        return redirect(f"/login?error={e.code}")

    # result.sub is the verified pairwise subject — key your User record on it.
    user, _ = User.objects.get_or_create(logi_sub=result.sub, defaults={"email": result.email})
    request.session["user_id"] = user.id
    return redirect("/")
```

Identity claims (email/name) are **not** guaranteed on the id_token — fetch
them from `GET {issuer}/oauth/userinfo` with the returned `access_token` as a
Bearer token if you need more than `sub`/`email`.

## Public client (PKCE, no secret)

Omit `client_secret` and pass a `code_challenge` / `code_verifier`:

```python
logi = LogiAuthServer(client_id=client_id, redirect_uri=redirect_uri)  # no secret
url = logi.authorization_url(state=state, nonce=nonce, code_challenge=code_challenge)
result = logi.exchange_code_and_verify(code=code, nonce=nonce, code_verifier=code_verifier)
```

## API

```python
from logi_auth import LogiAuthServer, LogiSession, verify_id_token, LogiAuthError, IdTokenError, ServerError
```

### `LogiAuthServer(...)`

```python
LogiAuthServer(
    *,
    client_id: str,
    redirect_uri: str,
    client_secret: str | None = None,
    issuer: str = "https://api.1pass.dev",
    token_issuer: str = "https://api.1pass.dev",
    scopes: list[str] | None = None,        # default: ["openid", "profile:basic", "email"]
    jwks_cache_ttl: int = 3600,
)
```

- **`.authorization_url(*, state, nonce, scopes=None, code_challenge=None, prompt=None) -> str`**
  Builds the `/oauth/authorize` redirect URL.
- **`.exchange_code_and_verify(*, code, nonce, code_verifier=None) -> LogiSession`**
  Exchanges the authorization `code` for tokens, then verifies the returned
  `id_token` (signature via JWKS + `iss` + `aud` + `exp` + `nonce`, with a
  transparent single JWKS refetch on key rotation) before returning a
  `LogiSession`.

### `LogiSession`

Returned only once id_token verification has fully passed:

| Field | Type |
|-------|------|
| `sub` | `str` — verified pairwise subject |
| `email` | `str \| None` |
| `id_token` | `str` |
| `access_token` | `str` |
| `refresh_token` | `str \| None` |
| `expires_at` | `int \| None` — unix timestamp |
| `scope` | `str \| None` |
| `claims` | `dict` — full verified id_token claim set |

## Error handling

Both error types carry a `.code` string for programmatic branching (same
codes as the Ruby/Node/Web SDKs and the shared golden vectors).

`ServerError.code`:

| Code | Meaning |
|------|---------|
| `invalid_nonce` | Missing nonce — the sign-in session likely expired |
| `token_exchange_failed` | `/oauth/token` returned a non-2xx status or malformed body |
| `missing_id_token` | Token response had no `id_token` (was `openid` in scopes?) |
| `id_token_invalid` | id_token failed verification — `.detail` carries the underlying `IdTokenError.code` |
| `jwks_fetch_failed` | JWKS endpoint unreachable or returned a malformed document |
| `network_error` | Transport-level failure talking to the issuer |

`IdTokenError.code` (raised by `verify_id_token` directly, or wrapped into
`ServerError("id_token_invalid", ...)` by `exchange_code_and_verify`):

`malformed`, `missing_kid`, `unknown_kid`, `bad_signature`, `iss_mismatch`,
`aud_mismatch`, `expired`, `nonce_mismatch`, `missing_claim`, `at_hash_mismatch`.

```python
from logi_auth import ServerError

try:
    result = LOGI.exchange_code_and_verify(code=code, nonce=nonce)
except ServerError as e:
    logger.warning("logi sign-in failed: %s (%s)", e.code, e.detail)
    return redirect(f"/login?error={e.code}")
```

## Security

`exchange_code_and_verify` performs the full id_token verification —
signature against the issuer's JWKS, `iss`, `aud` (against your `client_id`),
`exp`, and `nonce` — **before** it ever returns a `sub`. Verifying on the
server, not just trusting a client-supplied token, is what closes the
cross-client account-takeover class of bug: a frontend alone cannot prove that
an id_token it received was actually minted for *your* `client_id`.

## License

Apache-2.0
