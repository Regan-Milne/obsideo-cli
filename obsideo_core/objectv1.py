"""obsideo-object-v1: the self-describing content format every Obsideo client
writes from 2026-09-29 on. Public spec: docs/object_format_v1.md; keep the two
in step. Reference implementation of both the writer and the reader.

Why a header. The earlier chunked format (obsideo-chunked-v1, chunked.py) kept
the per-file nonce and the chunk count in the coordinator's metadata, so a
stored object could not be opened without the coordinator. That breaks the
sovereign-recovery rule (design principle 2: your phrase plus any one live
provider holding your bytes is enough). Here every value a reader needs is in
the object itself, and the coordinator's metadata copy is a hint only.

    header (48 bytes, at offset 0):
        0   4  magic  b"OBSD"
        4   1  version 0x01
        5   1  key mode 0x01 = file key derived from the account data key
        6   2  reserved, zero
        8   8  file_nonce   (random per upload)
        16 16  key_salt     (random per upload)
        32  4  BE32 total_chunks
        36 12  reserved, zero
    file key    = HKDF-SHA256(ikm = account data key, salt = key_salt,
                              info = b"obsideo-file-key-v1", L = 32)
    nonce_i     = file_nonce || BE32(i)                          (12 bytes)
    AAD_i       = header || BE32(i)                              (52 bytes)
    chunk_i     = AES-256-GCM(file key, nonce_i, plaintext_i, AAD_i) = ct_i || tag_i(16)
    object      = header || chunk_0 || chunk_1 || ...

Chunk 0 holds P0 = 1 MiB - 48 - 16 = 1048512 plaintext bytes, every later
chunk P = 1 MiB - 16 = 1048560, so the header plus chunk 0 is exactly the
network's 1 MiB merkle chunk 0 and chunk i is merkle chunk i: a ranged fetch of
one merkle chunk decrypts on its own (chunk 0 needs nothing else, and any
other chunk needs only the 48-byte header). The file key is what a share link
hands out: HKDF cannot be run backwards, so a shared file reveals nothing
about the account key.

Everything streams: at most one chunk of plaintext and one of ciphertext is
held at a time, whatever the file size.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT = "obsideo-object-v1"
MAGIC = b"OBSD"
VERSION = 1
KEYMODE_DERIVED = 1
HEADER_LEN = 48
MERKLE = 1048576          # the network's merkle chunk, frozen
TAG_LEN = 16
P = MERKLE - TAG_LEN      # plaintext bytes in chunk i >= 1: 1048560
P0 = P - HEADER_LEN       # plaintext bytes in chunk 0: 1048512
FILE_NONCE_LEN = 8
KEY_SALT_LEN = 16
FILE_KEY_INFO = b"obsideo-file-key-v1"
MAX_CHUNKS = 2**32 - 1
MIN_OBJECT = HEADER_LEN + TAG_LEN   # an empty file: header + one bare tag


class FormatError(ValueError):
    """The bytes are not a well-formed obsideo-object-v1 object (bad magic,
    unknown version or key mode, truncated, trailing bytes, count mismatch)."""


class AuthError(Exception):
    """A chunk's GCM tag did not verify: wrong key, or the bytes were altered.
    A failure at chunk 0 almost always means the key is wrong; a later one
    means the stored object is damaged."""

    def __init__(self, index: int):
        super().__init__(f"chunk {index} failed authentication")
        self.index = index


@dataclass(frozen=True)
class Header:
    file_nonce: bytes
    key_salt: bytes
    total_chunks: int
    keymode: int = KEYMODE_DERIVED

    def pack(self) -> bytes:
        if len(self.file_nonce) != FILE_NONCE_LEN or len(self.key_salt) != KEY_SALT_LEN:
            raise ValueError("file_nonce must be 8 bytes and key_salt 16 bytes")
        if not 1 <= self.total_chunks <= MAX_CHUNKS:
            raise ValueError("total_chunks out of range")
        return (MAGIC + bytes([VERSION, self.keymode]) + bytes(2)
                + self.file_nonce + self.key_salt
                + self.total_chunks.to_bytes(4, "big") + bytes(12))

    @classmethod
    def parse(cls, b: bytes) -> "Header":
        """Parse the first 48 bytes of an object. Reserved bytes are ignored
        (they are authenticated through the AAD, so they cannot be altered)."""
        if len(b) < HEADER_LEN:
            raise FormatError(f"object is {len(b)} bytes, shorter than the {HEADER_LEN}-byte header")
        b = bytes(b[:HEADER_LEN])
        if b[:4] != MAGIC:
            raise FormatError("not an obsideo-object-v1 object (magic mismatch)")
        if b[4] != VERSION:
            raise FormatError(f"obsideo object version {b[4]} is newer than this client; upgrade obsideo-cli")
        if b[5] != KEYMODE_DERIVED:
            raise FormatError(f"obsideo object key mode {b[5]} is not supported by this client; upgrade obsideo-cli")
        total = int.from_bytes(b[32:36], "big")
        if total < 1:
            raise FormatError("header declares zero chunks")
        return cls(file_nonce=b[8:16], key_salt=b[16:32], total_chunks=total, keymode=b[5])


def is_v1(head: bytes) -> bool:
    """True if these leading bytes carry the v1 magic and version. Used by the
    offline recovery path, which has no metadata to go by."""
    return len(head) >= 5 and head[:4] == MAGIC and head[4] == VERSION


def file_key(data_key: bytes, key_salt: bytes) -> bytes:
    if len(data_key) != 32:
        raise ValueError("data key must be 32 bytes")
    if len(key_salt) != KEY_SALT_LEN:
        raise ValueError("key_salt must be 16 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=key_salt,
                info=FILE_KEY_INFO).derive(data_key)


def chunk_nonce(file_nonce: bytes, index: int) -> bytes:
    return file_nonce + index.to_bytes(4, "big")


def aad(header_bytes: bytes, index: int) -> bytes:
    return header_bytes + index.to_bytes(4, "big")


def chunk_count(plaintext_size: int) -> int:
    """Chunks for a plaintext of this size. The first chunk holds P0 bytes,
    every later one P. An empty file is one chunk holding only a tag."""
    if plaintext_size < 0:
        raise ValueError("negative size")
    if plaintext_size <= P0:
        return 1
    return 1 + -(-(plaintext_size - P0) // P)


def chunks_in_object(object_size: int) -> int:
    """Chunk count implied by a stored object's size (header + chunk 0 is
    merkle chunk 0, so this is a plain ceiling over 1 MiB)."""
    if object_size < MIN_OBJECT:
        raise FormatError(f"object is {object_size} bytes, shorter than the smallest v1 object ({MIN_OBJECT})")
    return -(-object_size // MERKLE)


def plaintext_size(object_size: int, total_chunks: int | None = None) -> int:
    """Plaintext bytes in a stored object of this size."""
    total = chunks_in_object(object_size) if total_chunks is None else total_chunks
    return object_size - HEADER_LEN - TAG_LEN * total


def object_size(plaintext_size_: int) -> int:
    return HEADER_LEN + plaintext_size_ + TAG_LEN * chunk_count(plaintext_size_)


def check_object_size(size: int, total_chunks: int) -> None:
    """Refuse a stored size that cannot hold exactly total_chunks chunks."""
    # The header sits inside merkle chunk 0, so only a one-chunk object has
    # the header in its minimum; a later last chunk can be a bare tag.
    low = max(MIN_OBJECT, (total_chunks - 1) * MERKLE + TAG_LEN)
    high = total_chunks * MERKLE
    if not low <= size <= high:
        raise FormatError(
            f"object is {size} bytes, which holds {chunks_in_object(size) if size >= MIN_OBJECT else 0} "
            f"chunk(s), but its header declares {total_chunks}")


def metadata_for() -> dict:
    """The coordinator-side hint. Everything a reader needs is in the object;
    this only lets a client pick the reader without fetching the first bytes."""
    return {"enc": FORMAT}


def enc_from_metadata(meta: dict | None) -> str | None:
    """The object's format tag from its metadata map, or None when absent.
    Key names are matched case-insensitively (S3 metadata names are case-
    insensitive and gateways return them in varying case)."""
    if not meta:
        return None
    for k, v in meta.items():
        if str(k).lower() == "enc":
            return None if v is None else str(v)
    return None


class _Reader:
    """Uniform read(n) over a file object or an iterable of byte strings;
    read(n) returns exactly n bytes unless the source is exhausted."""

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


def encrypt(data_key: bytes, plaintext: BinaryIO | Iterable[bytes] | bytes,
            size: int | None = None, *, file_nonce: bytes | None = None,
            key_salt: bytes | None = None) -> tuple[Iterator[bytes], Header]:
    """Encrypt to obsideo-object-v1. Returns (iterator of stored pieces, header).

    The first piece is header || chunk_0 (merkle chunk 0), every later piece
    one chunk. total_chunks is in the header, and the header is in every
    chunk's AAD, so the size must be known before the first chunk is sealed:
    pass `size` for a plain iterator; bytes and seekable files are measured.
    file_nonce and key_salt are random unless given (tests and the vector).
    """
    if len(data_key) != 32:
        raise ValueError("data key must be 32 bytes")
    measured = _source_size(plaintext)
    if size is None:
        size = measured
    elif measured is not None and size != measured:
        raise ValueError(f"size {size} does not match the source ({measured} bytes)")
    if size is None:
        raise ValueError("size is required for a non-seekable plaintext source")
    total = chunk_count(size)
    if total > MAX_CHUNKS:
        raise ValueError("file too large for obsideo-object-v1")
    header = Header(file_nonce=file_nonce or os.urandom(FILE_NONCE_LEN),
                    key_salt=key_salt or os.urandom(KEY_SALT_LEN), total_chunks=total)
    hb = header.pack()
    key = file_key(data_key, header.key_salt)
    src = memoryview(plaintext) if isinstance(plaintext, (bytes, bytearray)) else plaintext

    def gen() -> Iterator[bytes]:
        aead = AESGCM(key)
        reader = None if isinstance(src, memoryview) else _Reader(src)
        pos = 0
        for i in range(total):
            want = P0 if i == 0 else P
            if i == total - 1:
                want = size - pos
            if reader is None:
                piece = bytes(src[pos:pos + want])
            else:
                piece = reader.read(want)
            if len(piece) != want:
                raise FormatError(f"plaintext ended early at chunk {i}")
            pos += want
            sealed = aead.encrypt(chunk_nonce(header.file_nonce, i), piece, aad(hb, i))
            yield hb + sealed if i == 0 else sealed
        if reader is not None and reader.read(1):
            raise FormatError("plaintext is longer than the declared size")

    return gen(), header


def decrypt(data_key: bytes, ciphertext: BinaryIO | Iterable[bytes],
            object_size_: int | None = None) -> Iterator[bytes]:
    """Decrypt an obsideo-object-v1 object, yielding plaintext chunk by chunk.
    Needs nothing but the account data key and the stored bytes: the header
    is read from the stream. This is the sovereign-recovery path.

    Every chunk's tag is verified before its plaintext is yielded. The object
    must hold exactly the header's chunk count: all but the last full, the
    last between 16 bytes and 1 MiB, nothing after it. Anything else raises
    FormatError; a tag failure raises AuthError. Pass object_size_ (the
    Content-Length) when known and a count mismatch is refused before any
    chunk is decrypted. Plaintext yielded before an error was authentic, but
    the file as a whole is not: callers writing to disk must discard partial
    output on error.
    """
    if len(data_key) != 32:
        raise ValueError("data key must be 32 bytes")

    def gen() -> Iterator[bytes]:
        reader = _Reader(ciphertext)
        hb = reader.read(HEADER_LEN)
        header = Header.parse(hb)
        total = header.total_chunks
        if object_size_ is not None:
            check_object_size(object_size_, total)
        aead = AESGCM(file_key(data_key, header.key_salt))
        for i in range(total):
            last = i == total - 1
            want = MERKLE - HEADER_LEN if i == 0 else MERKLE
            chunk = reader.read(want)
            if not last and len(chunk) != want:
                raise FormatError(f"object ends at chunk {i} of {total}: fewer chunks than its header declares")
            if last:
                if len(chunk) < TAG_LEN:
                    raise FormatError(f"object ends at chunk {i} of {total}: fewer chunks than its header declares")
                if reader.read(1):
                    raise FormatError(f"object has bytes after chunk {i}: more chunks than its header declares ({total})")
            try:
                yield aead.decrypt(chunk_nonce(header.file_nonce, i), chunk, aad(hb, i))
            except InvalidTag:
                raise AuthError(i) from None

    return gen()
