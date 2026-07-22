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
        with urllib.request.urlopen(req, timeout=30, context=config.ssl_context()) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", "")
        except Exception:
            detail = ""
        raise LoginError(detail or f"HTTP {e.code}")
    except urllib.error.URLError as e:
        raise LoginError(f"could not reach {url}: {e.reason}")


def start(email: str, url: str | None = None, source: str | None = None) -> None:
    """Request a verification code be emailed to `email`.

    `source` is optional free-text attribution recorded on the account ("where
    did this signup come from"). It never gates signup. Defaults to "cli" so
    terminal signups stop being indistinguishable from raw API calls.
    """
    url = url or config.signup_url()
    payload = {"email": email, "source": source or "cli"}
    _post_json(f"{url}/v1/auth/start", payload)


def verify(email: str, code: str, url: str | None = None,
           referral_code: str | None = None) -> dict:
    """Verify the code + provision an account. Generates the local signing key,
    sends only its public half, persists the returned credentials. An optional
    referral_code (a friend's invite) grants the new account +1 GB. Returns the
    credential bundle.
    """
    url = url or config.signup_url()
    signing_pubkey = identity.get_or_create_signing_pubkey()
    payload = {
        "email": email,
        "code": code,
        "customer_signing_public_key": signing_pubkey,
    }
    if referral_code:
        payload["referral_code"] = referral_code
    creds = _post_json(f"{url}/v1/auth/verify", payload)
    config.write_credentials(creds)
    return creds
