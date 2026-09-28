"""obsideo-chunked-v1: round trips, tamper detection, chunk-count binding,
metadata parsing, and the cross-client test vector the browser must match."""

import hashlib
import io
import os
import unicodedata

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from obsideo_core import chunked
from obsideo_core.chunked import P, STRIDE, TAG_LEN

KEY = bytes(range(32))
NONCE = bytes.fromhex("a1b2c3d4e5f60718")


def _pattern(n: int) -> bytes:
    return bytes(k % 256 for k in range(n))


def _encrypt(pt: bytes, key=KEY, nonce=NONCE) -> tuple[list[bytes], int]:
    it, total = chunked.encrypt_chunked(key, pt, nonce)
    return list(it), total


def _decrypt(ct, total, key=KEY, nonce=NONCE, size=None) -> bytes:
    return b"".join(chunked.decrypt_chunked(key, ct, nonce, total, ciphertext_size=size))


def test_constants():
    assert P == 1048560
    assert STRIDE == P + TAG_LEN == 1048576  # stored chunks align with 1 MiB merkle chunks


@pytest.mark.parametrize("size", [0, 1, 1000, P - 1, P, P + 1, 2 * 1048576 + 12345])
def test_round_trip(size):
    pt = _pattern(size)
    chunks, total = _encrypt(pt)
    assert total == len(chunks) == max(1, -(-size // P))
    assert all(len(c) == STRIDE for c in chunks[:-1])
    assert TAG_LEN <= len(chunks[-1]) <= STRIDE
    ct = b"".join(chunks)
    assert chunked.plaintext_size(len(ct), total) == size
    assert (total - 1) * P + (len(chunks[-1]) - TAG_LEN) == size
    assert _decrypt(io.BytesIO(ct), total) == pt


def test_empty_file_is_one_bare_tag_chunk():
    chunks, total = _encrypt(b"")
    assert total == 1 and len(chunks) == 1 and len(chunks[0]) == TAG_LEN
    assert chunked.metadata_for(NONCE, total)["chunks"] == "1"
    assert _decrypt(io.BytesIO(chunks[0]), 1) == b""


def test_boundary_chunk_counts():
    assert chunked.chunk_count(0) == 1
    assert chunked.chunk_count(P) == 1
    assert chunked.chunk_count(P + 1) == 2
    assert chunked.chunk_count(2 * P) == 2


def test_sources_and_sinks_agree():
    """bytes, a seekable file, and a plain iterator (with size) produce identical
    ciphertext; decryption accepts a file object or an iterator of odd pieces."""
    pt = _pattern(P + 5000)
    from_bytes, total = _encrypt(pt)
    it, t2 = chunked.encrypt_chunked(KEY, io.BytesIO(pt), NONCE)
    from_file = list(it)
    pieces = (pt[i:i + 7777] for i in range(0, len(pt), 7777))
    it, t3 = chunked.encrypt_chunked(KEY, pieces, NONCE, size=len(pt))
    from_iter = list(it)
    assert total == t2 == t3 == 2
    assert from_bytes == from_file == from_iter
    ct = b"".join(from_bytes)
    odd = (ct[i:i + 999] for i in range(0, len(ct), 999))
    assert _decrypt(odd, total) == pt


def test_iterator_source_needs_size():
    with pytest.raises(ValueError):
        chunked.encrypt_chunked(KEY, iter([b"abc"]), NONCE)


def test_iterator_source_shorter_than_declared_is_refused():
    it, _ = chunked.encrypt_chunked(KEY, iter([b"abc"]), NONCE, size=10)
    with pytest.raises(chunked.ChunkedFormatError):
        list(it)


def test_encrypt_streams_lazily():
    """The first chunk is sealed after reading about one chunk of input, not the
    whole file: memory stays bounded by the chunk size."""
    consumed = [0]
    piece = 64 * 1024

    def src():
        for _ in range((3 * P) // piece + 1):
            consumed[0] += piece
            yield b"\0" * piece

    total_size = ((3 * P) // piece + 1) * piece
    it, total = chunked.encrypt_chunked(KEY, src(), NONCE, size=total_size)
    first = next(it)
    assert len(first) == STRIDE
    assert consumed[0] <= P + piece


def test_flipped_byte_fails_that_chunk():
    pt = _pattern(2 * P + 10)
    chunks, total = _encrypt(pt)
    for victim in range(total):
        bad = [bytearray(c) for c in chunks]
        bad[victim][5] ^= 0x01
        with pytest.raises(chunked.ChunkAuthError) as e:
            _decrypt(io.BytesIO(b"".join(bad)), total)
        assert e.value.index == victim


def test_wrong_key_fails_at_chunk_zero():
    chunks, total = _encrypt(_pattern(1000))
    with pytest.raises(chunked.ChunkAuthError) as e:
        _decrypt(io.BytesIO(b"".join(chunks)), total, key=os.urandom(32))
    assert e.value.index == 0


def test_wrong_file_nonce_fails():
    chunks, total = _encrypt(_pattern(1000))
    with pytest.raises(chunked.ChunkAuthError):
        _decrypt(io.BytesIO(b"".join(chunks)), total, nonce=bytes(8))


def test_chunk_count_mismatch_refused():
    pt = _pattern(2 * P + 10)
    chunks, total = _encrypt(pt)
    ct = b"".join(chunks)
    assert total == 3
    short = b"".join(chunks[:-1])
    # With the stored size known (every real download): refused before any
    # chunk is decrypted, as a structural error, not as a tag failure.
    for claimed, body in ((total + 1, ct), (total - 1, ct), (total, short)):
        with pytest.raises(chunked.ChunkedFormatError):
            chunked.decrypt_chunked(KEY, io.BytesIO(body), NONCE, claimed,
                                    ciphertext_size=len(body))
    # Pure streaming (size unknown): still refused. A wrong declared count
    # fails chunk 0's tag, because the count is in every chunk's AAD; a
    # truncated object runs out before its declared last chunk.
    for claimed in (total + 1, total - 1):
        with pytest.raises(chunked.ChunkAuthError):
            _decrypt(io.BytesIO(ct), claimed)
    with pytest.raises(chunked.ChunkedFormatError):
        _decrypt(io.BytesIO(short), total)


def test_check_ciphertext_size_bounds():
    chunked.check_ciphertext_size(TAG_LEN, 1)
    chunked.check_ciphertext_size(STRIDE, 1)
    chunked.check_ciphertext_size(STRIDE + TAG_LEN, 2)
    for size, total in ((TAG_LEN - 1, 1), (STRIDE + 1, 1), (STRIDE, 2), (0, 1)):
        with pytest.raises(chunked.ChunkedFormatError):
            chunked.check_ciphertext_size(size, total)


def test_dropping_the_tail_and_lowering_the_count_still_fails():
    """AAD binds total_chunks, so a truncation that also rewrites the metadata
    count does not decrypt."""
    chunks, total = _encrypt(_pattern(2 * P + 10))
    with pytest.raises(chunked.ChunkAuthError):
        _decrypt(io.BytesIO(b"".join(chunks[:-1])), total - 1)


def test_reordered_chunks_fail():
    chunks, total = _encrypt(_pattern(3 * P))
    swapped = [chunks[1], chunks[0], chunks[2]]
    with pytest.raises(chunked.ChunkAuthError) as e:
        _decrypt(io.BytesIO(b"".join(swapped)), total)
    assert e.value.index == 0


def test_invalid_total_refused_up_front():
    for bad in (0, -1, 2**32):
        with pytest.raises(chunked.ChunkedFormatError):
            chunked.decrypt_chunked(KEY, io.BytesIO(b""), NONCE, bad)


# ── metadata ────────────────────────────────────────────────────────────────

def test_params_absent_means_legacy():
    assert chunked.params_from_metadata(None) is None
    assert chunked.params_from_metadata({}) is None
    assert chunked.params_from_metadata({"mtime": "1614816000"}) is None


def test_params_valid():
    meta = {"enc": "obsideo-chunked-v1", "nonce": "0000000000000001", "chunks": "3"}
    assert chunked.params_from_metadata(meta) == (bytes.fromhex("0000000000000001"), 3)


def test_params_key_names_are_case_insensitive():
    meta = {"Enc": "obsideo-chunked-v1", "NONCE": "00000000000000ff", "Chunks": "1"}
    assert chunked.params_from_metadata(meta) == (bytes.fromhex("00000000000000ff"), 1)


def test_metadata_for_round_trips():
    meta = chunked.metadata_for(NONCE, 7)
    assert meta == {"enc": "obsideo-chunked-v1", "nonce": "a1b2c3d4e5f60718", "chunks": "7"}
    assert chunked.params_from_metadata(meta) == (NONCE, 7)


def test_params_unknown_format_refused():
    with pytest.raises(chunked.UnknownFormatError) as e:
        chunked.params_from_metadata({"enc": "obsideo-chunked-v2", "nonce": "00" * 8, "chunks": "1"})
    assert str(e.value) == "unknown encryption format obsideo-chunked-v2; upgrade obsideo-cli"


@pytest.mark.parametrize("nonce", [None, "", "000000000000001", "00000000000000001",
                                   "000000000000000G", "00000000000000FF", 5])
def test_params_bad_nonce(nonce):
    meta = {"enc": "obsideo-chunked-v1", "chunks": "1"}
    if nonce is not None:
        meta["nonce"] = nonce
    with pytest.raises(chunked.ChunkedFormatError):
        chunked.params_from_metadata(meta)


@pytest.mark.parametrize("chunks", [None, "", "0", "-1", "01", "1.0", "abc", " 3", "4294967296", 3])
def test_params_bad_chunks(chunks):
    meta = {"enc": "obsideo-chunked-v1", "nonce": "0000000000000001"}
    if chunks is not None:
        meta["chunks"] = chunks
    with pytest.raises(chunked.ChunkedFormatError):
        chunked.params_from_metadata(meta)


# ── cross-client test vector ────────────────────────────────────────────────
# The browser implementation must reproduce these numbers byte for byte.

def _phrase_data_key(phrase: str) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", phrase).encode(),
                               b"mnemonic", 2048, 64)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"obsideo-phrase-v1/data-key").derive(seed)


def _merkle_root(data: bytes) -> str:
    """The network's merkle root: 1 MiB chunks, leaf = SHA3-512(SHA-256(str(i) +
    hex(chunk))), zero-padded to a power of two, parent = SHA3-512(l || r)."""
    size = 1048576
    leaves = []
    for i in range(-(-len(data) // size)):
        h = hashlib.sha256((str(i) + data[i * size:(i + 1) * size].hex()).encode()).digest()
        leaves.append(hashlib.sha3_512(h).digest())
    if len(leaves) == 1:
        return leaves[0].hex()
    width = 1
    while width < len(leaves):
        width <<= 1
    leaves += [bytes(64)] * (width - len(leaves))
    while len(leaves) > 1:
        leaves = [hashlib.sha3_512(leaves[i] + leaves[i + 1]).digest()
                  for i in range(0, len(leaves), 2)]
    return leaves[0].hex()


def test_cross_client_vector():
    key = _phrase_data_key(" ".join(["abandon"] * 11 + ["about"]))
    assert key.hex() == "05d4e219677ac3fdbaa10e86b8ef2598c34edfa31ea8b4f14c670ca0ea8c95e3"
    file_nonce = bytes.fromhex("0000000000000001")
    pt = _pattern(2 * 1048576 + 12345)

    chunks, total = _encrypt(pt, key=key, nonce=file_nonce)
    ct = b"".join(chunks)
    assert total == 3
    assert [len(c) for c in chunks] == [1048576, 1048576, 12393]
    assert len(ct) == 2109545
    assert hashlib.sha256(ct).hexdigest() == \
        "5c394de4fcfb785410d7ec7909c6119cace800e130cba938029983f94f496ad4"
    assert hashlib.sha256(chunks[0]).hexdigest() == \
        "d32faa972573ff89c2e0250d9fa9ca65396cc61d28f464fcbebfc75ada88aeae"
    assert _merkle_root(ct) == (
        "358f99ff00d692d7e0c8e85d43345576cf7b8a27a5ddd22ef37aed9fac7fd6cd"
        "221fb04015fff13e0d7e03f669cf0be30f4a6ae518f683e7828f4c62a55481c9")
    assert chunked.metadata_for(file_nonce, total) == \
        {"enc": "obsideo-chunked-v1", "nonce": "0000000000000001", "chunks": "3"}
    assert _decrypt(io.BytesIO(ct), total, key=key, nonce=file_nonce) == pt
