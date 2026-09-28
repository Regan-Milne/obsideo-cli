"""Offline recovery: a raw stored object plus the account key -> the file.

The sovereign-recovery drill for the content formats (design principle 2):
nothing here talks to the coordinator, the gateway, or the network. Give it
the bytes a storage provider holds and the phrase (or the 64-hex data key)
and it writes the plaintext, or refuses with a reason and writes nothing.

Formats told apart by the bytes alone:
  * "OBSD" + version 1 at offset 0  -> obsideo-object-v1 (objectv1.decrypt)
  * anything else                   -> legacy single stream nonce(12)||ct||tag(16)
obsideo-chunked-v1 cannot be recovered this way: its nonce lived only in the
coordinator's metadata, which is the reason obsideo-object-v1 exists.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from obsideo_core import objectv1

PHRASE_INFO = b"obsideo-phrase-v1/data-key"
_PIECE = 1024 * 1024


class RecoverError(Exception):
    """str() is the message for the user. Nothing was written."""


def data_key_from_phrase(phrase: str) -> bytes:
    """The 12-word phrase -> account data key, the shared recipe:
    seed = PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic", 2048, 64);
    key = HKDF-SHA256(seed, info = "obsideo-phrase-v1/data-key", 32).
    The words are not checked against the BIP-39 list here; a mistyped word
    simply yields a key that does not open the file."""
    words = phrase.strip().split()
    if len(words) != 12:
        raise RecoverError(f"expected 12 words, got {len(words)}")
    normalized = unicodedata.normalize("NFKD", " ".join(w.lower() for w in words))
    seed = hashlib.pbkdf2_hmac("sha512", normalized.encode(), b"mnemonic", 2048, 64)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PHRASE_INFO).derive(seed)


def data_key_from_hex(value: str) -> bytes:
    raw = value.strip()
    if "=" in raw:
        raw = raw.split("=", 1)[1].strip()
    raw = raw.strip("'\"")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise RecoverError("the key must be 64 hexadecimal characters") from None
    if len(key) != 32:
        raise RecoverError(f"the key must be 32 bytes (64 hex characters), got {len(key)}")
    return key


def recover(stored: Path, out: Path, data_key: bytes) -> dict:
    """Decrypt `stored` into `out`. Returns {"format": str, "size": int}.
    Writes to a hidden partial file and renames it into place only after
    every byte authenticated, so a failure leaves nothing behind."""
    if len(data_key) != 32:
        raise RecoverError("data key must be 32 bytes")
    try:
        total = stored.stat().st_size
    except OSError as e:
        raise RecoverError(f"cannot read {stored}: {e}") from None
    tmp = out.with_name(f".{out.name}.obsideo-partial")
    try:
        with open(stored, "rb") as src:
            head = src.read(objectv1.HEADER_LEN)
            src.seek(0)
            out.parent.mkdir(parents=True, exist_ok=True)
            size = 0
            with open(tmp, "wb") as dst:
                if objectv1.is_v1(head):
                    fmt = objectv1.FORMAT
                    try:
                        for piece in objectv1.decrypt(data_key, src, total):
                            dst.write(piece)
                            size += len(piece)
                    except objectv1.AuthError as e:
                        if e.index == 0:
                            raise RecoverError("this key does not open the object (chunk 0 failed to authenticate)") from None
                        raise RecoverError(f"chunk {e.index} failed to authenticate: the stored bytes are damaged") from None
                    except objectv1.FormatError as e:
                        raise RecoverError(f"the stored object is damaged or incomplete ({e})") from None
                else:
                    fmt = "single-stream"
                    blob = src.read()
                    if len(blob) < 28:
                        raise RecoverError("too short to be an encrypted object")
                    try:
                        plain = AESGCM(data_key).decrypt(blob[:12], blob[12:], None)
                    except Exception:
                        raise RecoverError("this key does not open the object, or it is not one of the formats "
                                           "this command can recover (a chunked-v1 object needs its coordinator "
                                           "metadata; it is re-keyed by Drive)") from None
                    dst.write(plain)
                    size = len(plain)
        os.replace(tmp, out)
        return {"format": fmt, "size": size}
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
