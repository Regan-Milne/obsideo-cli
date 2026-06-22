"""Config + credential loading for the Obsideo core.

Everything lives under ~/.obsideo:
    credentials   # OBSIDEO_S3_* + OBSIDEO_ACCOUNT_TOKEN (written by `obsideo login`)
    config.json   # user settings (default bucket, encrypt flag, sync dir, cwd)
    data.key      # account data-encryption key (see crypto.py)
    signing.key   # Ed25519 signing private key (see identity.py)
"""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".obsideo"
CREDENTIALS_FILE = CONFIG_DIR / "credentials"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "bucket": "obsideo",
    "encrypt": True,          # encrypt file contents
    "encrypt_names": True,    # encrypt file/folder names (metadata privacy)
    "sync_dir": str(Path.home() / "obsideo-sync"),
}

_DEFAULT_ENDPOINT = "https://s3.obsideo.io"
_DEFAULT_REGION = "us-east-1"

# Sent on every request to the signup shim. A descriptive User-Agent avoids
# Cloudflare's default-`Python-urllib` bot block (HTTP 403 / error 1010) that
# fronts signup.obsideo.io; without it, `obsideo login` and usage lookups fail.
try:
    from importlib.metadata import version as _pkg_version, PackageNotFoundError
    try:
        _VERSION = _pkg_version("obsideo-cloud")
    except PackageNotFoundError:
        _VERSION = "0.2.0"
except Exception:
    _VERSION = "0.2.0"

USER_AGENT = f"obsideo-cloud/{_VERSION}"


def write_secret_file(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows


def _load_env_file(path: Path) -> None:
    """Load key=value pairs into os.environ (no-overwrite)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip("'\""))


# Load saved credentials into the environment on import (no-overwrite, so explicit
# env vars still win). storage.py reads OBSIDEO_S3_* from the environment.
_load_env_file(CREDENTIALS_FILE)


# ── User config ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text()))
        except Exception:
            pass
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ── Credentials ─────────────────────────────────────────────────────────────

def write_credentials(creds: dict) -> None:
    """Persist the credential bundle returned by `obsideo login`."""
    lines = [
        f"OBSIDEO_S3_ENDPOINT={creds.get('endpoint', _DEFAULT_ENDPOINT)}",
        f"OBSIDEO_S3_ACCESS_KEY={creds['access_key']}",
        f"OBSIDEO_S3_SECRET_KEY={creds['secret_key']}",
        f"OBSIDEO_S3_BUCKET={creds.get('bucket', DEFAULT_CONFIG['bucket'])}",
        f"OBSIDEO_S3_REGION={creds.get('region', _DEFAULT_REGION)}",
    ]
    if creds.get("account_token"):
        lines.append(f"OBSIDEO_ACCOUNT_TOKEN={creds['account_token']}")
    write_secret_file(CREDENTIALS_FILE, "\n".join(lines) + "\n")
    # Reflect immediately for the current process (write_secret_file already wrote
    # the file; force these into env even if already set from a prior session).
    os.environ["OBSIDEO_S3_ENDPOINT"] = creds.get("endpoint", _DEFAULT_ENDPOINT)
    os.environ["OBSIDEO_S3_ACCESS_KEY"] = creds["access_key"]
    os.environ["OBSIDEO_S3_SECRET_KEY"] = creds["secret_key"]
    os.environ["OBSIDEO_S3_BUCKET"] = creds.get("bucket", DEFAULT_CONFIG["bucket"])
    os.environ["OBSIDEO_S3_REGION"] = creds.get("region", _DEFAULT_REGION)
    if creds.get("account_token"):
        os.environ["OBSIDEO_ACCOUNT_TOKEN"] = creds["account_token"]


def is_logged_in() -> bool:
    return bool(os.environ.get("OBSIDEO_S3_ACCESS_KEY") and os.environ.get("OBSIDEO_S3_SECRET_KEY"))


def account_token() -> str | None:
    return os.environ.get("OBSIDEO_ACCOUNT_TOKEN")


def signup_url() -> str:
    return os.environ.get("OBSIDEO_SIGNUP_URL", "https://signup.obsideo.io")
