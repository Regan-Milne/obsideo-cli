"""Account-level AES-256-GCM encryption for the general CLI.

One data key per account, held locally at ~/.obsideo/data.key. Every file is
encrypted with that key and a fresh random nonce (prepended). Any file the
account uploaded can be decrypted with this one key, which is what makes
browse/download/sync work across machines — copy this key to a new machine and
everything is readable.

This differs from the mlvault extension's per-run keys (immutable ML bundles); a
general file store wants one stable key. Lose the key, lose the data — by design.
Back it up alongside your credentials.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from obsideo_core import config

DATA_KEY_FILE = config.CONFIG_DIR / "data.key"


def data_key() -> bytes:
    """Load or generate the 32-byte account data key."""
    env = os.environ.get("OBSIDEO_DATA_KEY", "").strip()
    if env:
        return bytes.fromhex(env)
    if DATA_KEY_FILE.exists():
        return bytes.fromhex(DATA_KEY_FILE.read_text().strip())
    key = os.urandom(32)
    config.write_secret_file(DATA_KEY_FILE, key.hex())
    return key


def encrypt(data: bytes) -> bytes:
    """AES-256-GCM. Returns nonce(12) + ciphertext+tag."""
    key = data_key()
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(blob: bytes) -> bytes:
    """Inverse of encrypt. Raises on auth failure / wrong key."""
    key = data_key()
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def has_data_key() -> bool:
    """True if a key is already materialised for this config dir. Callers use
    this to detect the dangerous case: a machine with no key signing in to an
    account that already holds objects, where generating a fresh key silently
    orphans everything already uploaded."""
    return bool(os.environ.get("OBSIDEO_DATA_KEY", "").strip()) or DATA_KEY_FILE.exists()


def data_key_fingerprint() -> str:
    """A short, non-secret identifier for the current key: the first 16 hex
    chars of its SHA-256. Safe to print, log, or read down a phone line. Two
    machines showing the same fingerprint hold the same key; different
    fingerprints mean each can only read what it wrote."""
    import hashlib
    return hashlib.sha256(data_key()).hexdigest()[:16]


def import_data_key(value: str, *, force: bool = False) -> None:
    """Install a data key from an exported value.

    Accepts the bare 64-char hex key or the full `OBSIDEO_DATA_KEY=<hex>` line
    that `key export` prints, so pasting either works. Refuses to overwrite an
    existing key unless force is set: overwriting is exactly as destructive as
    losing the file, and it is not obvious from the command name.
    """
    raw = value.strip()
    if "=" in raw:
        raw = raw.split("=", 1)[1].strip()
    raw = raw.strip("'\"")
    try:
        key = bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError("Not a valid key: expected 64 hexadecimal characters.") from e
    if len(key) != 32:
        raise ValueError(f"Not a valid key: expected 32 bytes (64 hex chars), got {len(key)}.")
    if DATA_KEY_FILE.exists() and not force:
        raise FileExistsError(
            f"A key already exists at {DATA_KEY_FILE}. Importing over it makes anything "
            "encrypted with the current key unreadable. Back it up with 'obsideo key export' "
            "first, then re-run with --force."
        )
    config.write_secret_file(DATA_KEY_FILE, key.hex())


def data_key_backup_hint() -> str:
    return f"OBSIDEO_DATA_KEY={data_key().hex()}"
