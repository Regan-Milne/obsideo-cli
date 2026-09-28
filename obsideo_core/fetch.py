"""Download one object and write its plaintext to disk: the single restore path
shared by `get` and `sync pull`.

Three content formats exist and the object's metadata says which one it is:
  * no metadata["enc"]              -> legacy single stream (crypto.decrypt)
  * enc == "obsideo-object-v1"      -> self-describing (objectv1.decrypt, streamed)
  * enc == "obsideo-chunked-v1"     -> older chunked (chunked.decrypt_chunked, streamed)
  * any other enc                   -> refused; never guessed

A file that does not decrypt is never written. The old behaviour (save the
ciphertext under the requested name and report success) produced a file that
looked restored and was not; it now takes an explicit `raw=True`.
"""

from __future__ import annotations

import os
from pathlib import Path

from obsideo_core import chunked, crypto, objectv1, storage

_COPY_PIECE = 1024 * 1024


class RestoreError(Exception):
    """A download that could not be turned into plaintext. str() is the
    message to show the user; nothing was written to disk."""


def _key_message(name: str) -> str:
    return (f"Could not decrypt {name}: this key does not open it "
            "(stored with different 12 words or a different data key).")


def _partial_path(local: Path) -> Path:
    return local.with_name(f".{local.name}.obsideo-partial")


def restore(remote_key: str, local: Path, *, raw: bool = False,
            name: str | None = None) -> dict:
    """Fetch `remote_key` and write it to `local`.

    Returns {"size": bytes written, "encrypted": bool, "format": str}.
    Raises FileNotFoundError if the object is absent, RestoreError if it cannot
    be decrypted (wrong key, damaged, unknown format). Output goes to a hidden
    partial file first and is renamed into place only once every byte has
    authenticated, so a failure leaves nothing behind, not a truncated file.
    """
    name = name or remote_key.rsplit("/", 1)[-1]
    body, meta, stored_size = storage.open_object(remote_key)
    tmp = _partial_path(local)
    try:
        params = None
        v1 = False
        if raw:
            fmt = "raw"
            encrypted = False
        else:
            if objectv1.enc_from_metadata(meta) == objectv1.FORMAT:
                v1 = True
                fmt = objectv1.FORMAT
            else:
                try:
                    params = chunked.params_from_metadata(meta)
                except (chunked.UnknownFormatError, chunked.ChunkedFormatError) as e:
                    raise RestoreError(f"Could not decrypt {name}: {e}") from None
                fmt = chunked.FORMAT if params else "single-stream"
            encrypted = True
            key = crypto.data_key()

        local.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with open(tmp, "wb") as out:
            if raw:
                while True:
                    piece = body.read(_COPY_PIECE)
                    if not piece:
                        break
                    out.write(piece)
                    size += len(piece)
            elif v1:
                try:
                    for piece in objectv1.decrypt(key, body, stored_size):
                        out.write(piece)
                        size += len(piece)
                except objectv1.AuthError as e:
                    if e.index == 0:
                        raise RestoreError(_key_message(name)) from None
                    raise RestoreError(
                        f"Could not decrypt {name}: chunk {e.index} failed authentication, "
                        "so the stored object is damaged.") from None
                except objectv1.FormatError as e:
                    raise RestoreError(
                        f"Could not decrypt {name}: the stored object is damaged or incomplete ({e}).") from None
            elif params:
                file_nonce, total = params
                try:
                    for piece in chunked.decrypt_chunked(key, body, file_nonce, total,
                                                         ciphertext_size=stored_size):
                        out.write(piece)
                        size += len(piece)
                except chunked.ChunkAuthError as e:
                    if e.index == 0:
                        raise RestoreError(_key_message(name)) from None
                    raise RestoreError(
                        f"Could not decrypt {name}: chunk {e.index} failed authentication, "
                        "so the stored object is damaged.") from None
                except chunked.ChunkedFormatError as e:
                    raise RestoreError(
                        f"Could not decrypt {name}: the stored object is damaged or incomplete ({e}).") from None
            else:
                blob = body.read()
                try:
                    plain = crypto.decrypt(blob)
                except Exception:
                    raise RestoreError(_key_message(name)) from None
                out.write(plain)
                size = len(plain)
        os.replace(tmp, local)
        return {"size": size, "encrypted": encrypted, "format": fmt}
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    finally:
        close = getattr(body, "close", None)
        if close:
            close()
