"""obsideo-chunked-v1: the chunked content format the browser app writes.

The browser cannot run AES-GCM incrementally (WebCrypto is one-shot), so Drive
encrypts a file as a sequence of independently sealed chunks instead of one
stream. This module reads (and, for tests and a future `put`, writes) that
format. The public spec is docs/chunked_encryption_spec.md; keep the two in
step.

    key          = the account data key (32 bytes)
    P            = 1048560 plaintext bytes per chunk (last one shorter)
    file_nonce   = 8 random bytes per upload
    nonce_i      = file_nonce || BE32(i)                          (12 bytes)
    AAD_i        = b"obsideo-chunked-v1" || BE32(i) || BE32(total_chunks)
    chunk_i      = AES-256-GCM(key, nonce_i, plaintext_i, AAD_i)  = ct_i || tag_i(16)
    object bytes = chunk_0 || chunk_1 || ... (no header)

Every stored chunk but the last is P + 16 = 1 MiB exactly, so ciphertext chunk
i is the network's merkle chunk i. The nonce is derived, never stored.

The per-file parameters travel out of band, in the object's metadata map:
    {"enc": "obsideo-chunked-v1", "nonce": "<16 lowercase hex>", "chunks": "<decimal>"}

Everything here streams: at most one chunk of plaintext and one of ciphertext
is held at a time, whatever the file size.
"""

from __future__ import annotations

import re
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "obsideo-chunked-v1"
_FORMAT_BYTES = FORMAT.encode("ascii")

P = 1048576 - 16          # plaintext bytes per chunk = 1048560
TAG_LEN = 16              # AES-GCM tag, appended to each chunk's ciphertext
STRIDE = P + TAG_LEN      # stored bytes per full chunk = ct_i || tag_i = 1 MiB
FILE_NONCE_LEN = 8
MAX_CHUNKS = 2**32 - 1    # the chunk index and count are BE32

_NONCE_RE = re.compile(r"^[0-9a-f]{16}$")
_CHUNKS_RE = re.compile(r"^[1-9][0-9]*$")


class ChunkedFormatError(ValueError):
    """The object or its parameters do not have the shape the format requires
    (malformed metadata, truncated object, wrong chunk count, trailing bytes)."""


class UnknownFormatError(ValueError):
    """metadata["enc"] names a format this client does not know. Never guess."""


class ChunkAuthError(Exception):
    """A chunk's GCM tag did not verify: wrong key, or the bytes were altered.
    `index` is the failing chunk; a failure at chunk 0 almost always means the
    key is wrong, a later one means the stored object is damaged."""

    def __init__(self, index: int):
        super().__init__(f"chunk {index} failed authentication")
        self.index = index


def aad(index: int, total_chunks: int) -> bytes:
    """AAD_i = ASCII("obsideo-chunked-v1") || BE32(i) || BE32(total_chunks).
    Binds each chunk to its position and to the file's length, so chunks cannot
    be reordered, duplicated, or dropped from the end undetected."""
    return _FORMAT_BYTES + index.to_bytes(4, "big") + total_chunks.to_bytes(4, "big")


def chunk_nonce(file_nonce: bytes, index: int) -> bytes:
    """nonce_i = file_nonce (8 bytes) || BE32(i)."""
    return file_nonce + index.to_bytes(4, "big")


def chunk_count(plaintext_size: int) -> int:
    """Chunks for a plaintext of this size. An empty file is one chunk holding
    only a tag, so even a zero-byte object is authenticated."""
    if plaintext_size < 0:
        raise ValueError("negative size")
    return max(1, -(-plaintext_size // P))


def check_ciphertext_size(ciphertext_size: int, total_chunks: int) -> None:
    """Raise ChunkedFormatError unless an object of this size can hold exactly
    total_chunks chunks: (total-1) full chunks plus a last one of TAG_LEN..STRIDE
    bytes. Lets a reader refuse a count mismatch before decrypting anything."""
    low = (total_chunks - 1) * STRIDE + TAG_LEN
    high = total_chunks * STRIDE
    if not low <= ciphertext_size <= high:
        held = -(-ciphertext_size // STRIDE) if ciphertext_size > 0 else 0
        raise ChunkedFormatError(
            f"object is {ciphertext_size} bytes, which holds {held} chunk(s), "
            f"but its metadata declares {total_chunks}")


def plaintext_size(ciphertext_size: int, total_chunks: int) -> int:
    """Plaintext size from the stored object size:
    (total_chunks - 1) * P + (len(last ct chunk) - 16), which is the same as
    ciphertext_size - 16 * total_chunks since every chunk adds one tag."""
    return ciphertext_size - total_chunks * TAG_LEN


def metadata_for(file_nonce: bytes, total_chunks: int) -> dict:
    """The metadata map an uploader stores alongside the object."""
    return {"enc": FORMAT, "nonce": file_nonce.hex(), "chunks": str(total_chunks)}


def params_from_metadata(meta: dict | None) -> tuple[bytes, int] | None:
    """(file_nonce, total_chunks) if the object is obsideo-chunked-v1, None if it
    carries no "enc" key (the legacy single-stream format).

    Raises UnknownFormatError for any other "enc" value and ChunkedFormatError
    for a chunked object whose parameters are missing or malformed. Keys are
    matched case-insensitively (S3 metadata names are case-insensitive and the
    gateway may return them in any case); values are strict.
    """
    if not meta:
        return None
    lowered = {str(k).lower(): v for k, v in meta.items()}
    enc = lowered.get("enc")
    if enc is None:
        return None
    if enc != FORMAT:
        raise UnknownFormatError(f"unknown encryption format {enc}; upgrade obsideo-cli")
    nonce_hex = lowered.get("nonce")
    chunks = lowered.get("chunks")
    if not isinstance(nonce_hex, str) or not _NONCE_RE.match(nonce_hex):
        raise ChunkedFormatError(f"{FORMAT} object has a malformed nonce: {nonce_hex!r}")
    if not isinstance(chunks, str) or not _CHUNKS_RE.match(chunks):
        raise ChunkedFormatError(f"{FORMAT} object has a malformed chunk count: {chunks!r}")
    total = int(chunks)
    if total > MAX_CHUNKS:
        raise ChunkedFormatError(f"{FORMAT} chunk count out of range: {total}")
    return bytes.fromhex(nonce_hex), total


def _check_params(key: bytes, file_nonce: bytes) -> None:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(file_nonce) != FILE_NONCE_LEN:
        raise ValueError(f"file_nonce must be {FILE_NONCE_LEN} bytes")


class _Reader:
    """Uniform read(n) over a file object or an iterable of byte strings, with
    read(n) returning exactly n bytes unless the source is exhausted."""

    def __init__(self, src):
        if hasattr(src, "read"):
            self._read = src.read
            self._it = None
        else:
            self._read = None
            self._it = iter(src)
        self._buf = bytearray()

    def read(self, n: int) -> bytes:
        if self._read is not None:
            out = bytearray()
            while len(out) < n:
                piece = self._read(n - len(out))
                if not piece:
                    break
                out += piece
            return bytes(out)
        while len(self._buf) < n:
            try:
                piece = next(self._it)
            except StopIteration:
                break
            self._buf += piece
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def _source_size(src) -> int | None:
    if isinstance(src, (bytes, bytearray, memoryview)):
        return len(src)
    if hasattr(src, "seek") and hasattr(src, "tell"):
        try:
            if hasattr(src, "seekable") and not src.seekable():
                return None
            here = src.tell()
            end = src.seek(0, 2)
            src.seek(here)
            return end - here
        except (OSError, ValueError):
            return None
    return None


def encrypt_chunked(key: bytes, plaintext: BinaryIO | Iterable[bytes] | bytes,
                    file_nonce: bytes, size: int | None = None) -> tuple[Iterator[bytes], int]:
    """Encrypt to obsideo-chunked-v1. Returns (iterator of ciphertext chunks,
    total_chunks).

    total_chunks is part of every chunk's AAD, so it must be known before the
    first chunk is sealed: pass `size` for a plain iterator; bytes and seekable
    file objects are measured. The iterator yields each chunk as it is sealed
    and raises ChunkedFormatError if the source turns out shorter or longer than
    the size the chunk count was computed from.
    """
    _check_params(key, file_nonce)
    measured = _source_size(plaintext)
    if size is None:
        size = measured
    elif measured is not None and size != measured:
        raise ValueError(f"size {size} does not match the source ({measured} bytes)")
    if size is None:
        raise ValueError("size is required for a non-seekable plaintext source")
    total = chunk_count(size)
    if total > MAX_CHUNKS:
        raise ValueError("file too large for obsideo-chunked-v1")
    src = memoryview(plaintext) if isinstance(plaintext, (bytes, bytearray)) else plaintext

    def gen() -> Iterator[bytes]:
        aead = AESGCM(key)
        if isinstance(src, memoryview):
            for i in range(total):
                yield aead.encrypt(chunk_nonce(file_nonce, i), bytes(src[i * P:(i + 1) * P]),
                                   aad(i, total))
            return
        reader = _Reader(src)
        for i in range(total):
            want = P if i < total - 1 else size - (total - 1) * P
            piece = reader.read(want)
            if len(piece) != want:
                raise ChunkedFormatError(f"plaintext ended early at chunk {i}")
            yield aead.encrypt(chunk_nonce(file_nonce, i), piece, aad(i, total))
        if reader.read(1):
            raise ChunkedFormatError("plaintext is longer than the declared size")

    return gen(), total


def decrypt_chunked(key: bytes, ciphertext: BinaryIO | Iterable[bytes],
                    file_nonce: bytes, total_chunks: int,
                    ciphertext_size: int | None = None) -> Iterator[bytes]:
    """Decrypt obsideo-chunked-v1, yielding plaintext chunk by chunk.

    Every chunk's tag is verified before its plaintext is yielded. The stored
    object must hold exactly `total_chunks` chunks: all but the last full
    (STRIDE bytes), the last between TAG_LEN and STRIDE bytes, nothing after it.
    Anything else raises ChunkedFormatError. A tag failure raises ChunkAuthError.

    Pass `ciphertext_size` when it is known (the object's Content-Length) and a
    count mismatch is refused before any chunk is decrypted. Without it the
    mismatch is still refused, but may surface as a tag failure on the first
    chunk, since total_chunks is part of every chunk's AAD.

    Plaintext already yielded before an error was authentic, but the file as a
    whole is not: callers writing to disk must discard partial output on error.
    """
    _check_params(key, file_nonce)
    if not isinstance(total_chunks, int) or not 1 <= total_chunks <= MAX_CHUNKS:
        raise ChunkedFormatError(f"invalid chunk count: {total_chunks!r}")
    if ciphertext_size is not None:
        check_ciphertext_size(ciphertext_size, total_chunks)

    def gen() -> Iterator[bytes]:
        aead = AESGCM(key)
        reader = _Reader(ciphertext)
        for i in range(total_chunks):
            last = i == total_chunks - 1
            chunk = reader.read(STRIDE)
            if not last and len(chunk) != STRIDE:
                raise ChunkedFormatError(
                    f"object ends at chunk {i} of {total_chunks}: fewer chunks than its metadata declares")
            if last:
                if len(chunk) < TAG_LEN:
                    raise ChunkedFormatError(
                        f"object ends at chunk {i} of {total_chunks}: fewer chunks than its metadata declares")
                if reader.read(1):
                    raise ChunkedFormatError(
                        f"object has bytes after chunk {i}: more chunks than its metadata declares ({total_chunks})")
            try:
                yield aead.decrypt(chunk_nonce(file_nonce, i), chunk, aad(i, total_chunks))
            except InvalidTag:
                raise ChunkAuthError(i) from None

    return gen()
