"""Email-OTP login against the Obsideo signup shim (obsideo-signup).

UI-agnostic: callers (the CLI) handle prompting; these functions do the HTTP and
return data. No new dependencies (stdlib urllib).
"""

import json
import urllib.error
import urllib.request

from obsideo_core import config, identity


class LoginError(RuntimeError):
    pass


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": config.USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", "")
        except Exception:
            detail = ""
        raise LoginError(detail or f"HTTP {e.code}")
    except urllib.error.URLError as e:
        raise LoginError(f"could not reach {url}: {e.reason}")


def start(email: str, url: str | None = None) -> None:
    """Request a verification code be emailed to `email`."""
    url = url or config.signup_url()
    _post_json(f"{url}/v1/auth/start", {"email": email})


def verify(email: str, code: str, url: str | None = None) -> dict:
    """Verify the code + provision an account. Generates the local signing key,
    sends only its public half, persists the returned credentials. Returns the
    credential bundle.
    """
    url = url or config.signup_url()
    signing_pubkey = identity.get_or_create_signing_pubkey()
    creds = _post_json(f"{url}/v1/auth/verify", {
        "email": email,
        "code": code,
        "customer_signing_public_key": signing_pubkey,
    })
    config.write_credentials(creds)
    return creds
