"""obsideo-object-v1: round trips, header parsing, tamper detection, chunk
alignment, metadata-free recovery, and the cross-client test vector the
browser must match byte for byte."""

import hashlib
import io
import os
import unicodedata

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from obsideo_core import objectv1 as v1
from obsideo_core.objectv1 import HEADER_LEN, MERKLE, P, P0, TAG_LEN

KEY = bytes(range(32))
NONCE = bytes.fromhex("a1b2c3d4e5f60718")
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")


def _pattern(n: int) -> bytes:
    return bytes(k % 256 for k in range(n))


def _encrypt(pt, key=KEY, nonce=NONCE, salt=SALT, size=None):
    it, header = v1.encrypt(key, pt, size, file_nonce=nonce, key_salt=salt)
    return list(it), header


def _decrypt(obj, key=KEY, size=None) -> bytes:
    src = io.BytesIO(obj) if isinstance(obj, (bytes, bytearray)) else obj
    return b"".join(v1.decrypt(key, src, size))


def test_constants():
    assert HEADER_LEN == 48
    assert P == 1048560 and P0 == 1048512
    assert HEADER_LEN + P0 + TAG_LEN == MERKLE   # header + chunk 0 is merkle chunk 0
    assert P + TAG_LEN == MERKLE                 # chunk i >= 1 is merkle chunk i


@pytest.mark.parametrize("size", [0, 1, 1000, P0 - 1, P0, P0 + 1, P0 + P, P0 + P + 1, 2 * 1048576 + 12345])
def test_round_trip_and_alignment(size):
    pt = _pattern(size)
    pieces, header = _encrypt(pt)
    assert header.total_chunks == len(pieces) == v1.chunk_count(size)
    assert all(len(p) == MERKLE for p in pieces[:-1])
    obj = b"".join(pieces)
    assert len(obj) == v1.object_size(size)
    assert v1.plaintext_size(len(obj)) == size
    assert v1.chunks_in_object(len(obj)) == header.total_chunks
    assert obj[:HEADER_LEN] == header.pack()
    assert _decrypt(obj, size=len(obj)) == pt
    assert _decrypt(obj) == pt  # size unknown: still refused-or-correct, never wrong


def test_empty_file_is_header_plus_bare_tag():
    pieces, header = _encrypt(b"")
    assert header.total_chunks == 1 and len(pieces) == 1
    assert len(pieces[0]) == HEADER_LEN + TAG_LEN == v1.MIN_OBJECT
    assert _decrypt(pieces[0]) == b""


def test_chunk_count_boundaries():
    assert v1.chunk_count(0) == 1
    assert v1.chunk_count(P0) == 1
    assert v1.chunk_count(P0 + 1) == 2
    assert v1.chunk_count(P0 + P) == 2
    assert v1.chunk_count(P0 + P + 1) == 3


def test_header_layout_and_parse():
    h = v1.Header(file_nonce=NONCE, key_salt=SALT, total_chunks=7)
    b = h.pack()
    assert len(b) == HEADER_LEN
    assert b[:4] == b"OBSD" and b[4] == 1 and b[5] == 1 and b[6:8] == bytes(2)
    assert b[8:16] == NONCE and b[16:32] == SALT
    assert int.from_bytes(b[32:36], "big") == 7 and b[36:48] == bytes(12)
    assert v1.Header.parse(b) == h
    assert v1.is_v1(b) and not v1.is_v1(b"OBSE" + b[4:]) and not v1.is_v1(b"")


def test_reserved_bytes_are_ignored_by_parse_but_bound_by_aad():
    pieces, header = _encrypt(b"hello")
    obj = bytearray(b"".join(pieces))
    obj[40] ^= 1                    # a reserved byte
    v1.Header.parse(bytes(obj))     # parse does not care
    with pytest.raises(v1.AuthError):
        _decrypt(bytes(obj))        # the AAD does


@pytest.mark.parametrize("mutate, message", [
    (lambda b: b"XXXX" + b[4:], "magic"),
    (lambda b: b[:4] + bytes([2]) + b[5:], "version"),
    (lambda b: b[:5] + bytes([9]) + b[6:], "key mode"),
    (lambda b: b[:32] + bytes(4) + b[36:], "zero chunks"),
    (lambda b: b[:20], "shorter"),
])
def test_bad_headers_refused(mutate, message):
    pieces, _ = _encrypt(b"hello")
    with pytest.raises(v1.FormatError, match=message):
        _decrypt(mutate(b"".join(pieces)))


def test_wrong_key_fails_at_chunk_zero():
    pieces, _ = _encrypt(_pattern(P0 + 10))
    with pytest.raises(v1.AuthError) as e:
        _decrypt(b"".join(pieces), key=bytes(32))
    assert e.value.index == 0


def test_flipped_byte_fails_that_chunk_only_after_earlier_ones_pass():
    pt = _pattern(P0 + P + 5)
    pieces, _ = _encrypt(pt)
    obj = bytearray(b"".join(pieces))
    obj[MERKLE + 100] ^= 1            # inside chunk 1
    it = v1.decrypt(KEY, io.BytesIO(bytes(obj)))
    assert next(it) == pt[:P0]
    with pytest.raises(v1.AuthError) as e:
        next(it)
    assert e.value.index == 1


def test_truncated_and_extended_objects_refused():
    pt = _pattern(P0 + P + 5)
    pieces, header = _encrypt(pt)
    obj = b"".join(pieces)
    with pytest.raises(v1.FormatError, match="fewer chunks"):
        _decrypt(obj[:MERKLE + 10])
    with pytest.raises(v1.FormatError, match="more chunks"):
        _decrypt(obj + bytes(MERKLE))
    with pytest.raises(v1.AuthError):        # a stray byte inside the last merkle chunk: the tag catches it
        _decrypt(obj + b"x")
    with pytest.raises(v1.FormatError):
        v1.check_object_size(len(obj) + MERKLE, header.total_chunks)
    with pytest.raises(v1.FormatError):
        _decrypt(obj, size=len(obj) - MERKLE)


def test_reordered_chunks_fail():
    pt = _pattern(P0 + 2 * P)
    pieces, _ = _encrypt(pt)
    swapped = pieces[0] + pieces[2] + pieces[1]
    with pytest.raises(v1.AuthError):
        _decrypt(swapped)


def test_file_key_is_per_salt_and_one_way():
    k1 = v1.file_key(KEY, SALT)
    k2 = v1.file_key(KEY, bytes(16))
    assert k1 != k2 and len(k1) == 32
    assert k1 == v1.file_key(KEY, SALT)
    assert KEY not in k1 and k1 not in KEY


def test_two_uploads_of_the_same_bytes_differ():
    a, _ = v1.encrypt(KEY, b"same")
    b, _ = v1.encrypt(KEY, b"same")
    assert b"".join(a) != b"".join(b)


def test_streaming_sources_and_declared_size():
    pt = _pattern(P0 + 3)
    from_bytes = b"".join(_encrypt(pt)[0])
    from_file = b"".join(_encrypt(io.BytesIO(pt))[0])
    from_iter = b"".join(_encrypt(iter([pt[:100], pt[100:]]), size=len(pt))[0])
    assert from_bytes == from_file == from_iter
    with pytest.raises(ValueError):
        v1.encrypt(KEY, iter([pt]))
    with pytest.raises(v1.FormatError):
        list(v1.encrypt(KEY, iter([pt[:10]]), size=len(pt), file_nonce=NONCE, key_salt=SALT)[0])
    with pytest.raises(v1.FormatError):
        list(v1.encrypt(KEY, iter([pt + b"!"]), size=len(pt), file_nonce=NONCE, key_salt=SALT)[0])


def test_metadata_helpers():
    assert v1.metadata_for() == {"enc": "obsideo-object-v1"}
    assert v1.enc_from_metadata(None) is None
    assert v1.enc_from_metadata({}) is None
    assert v1.enc_from_metadata({"Enc": "obsideo-object-v1"}) == "obsideo-object-v1"
    assert v1.enc_from_metadata({"enc": "obsideo-chunked-v1"}) == "obsideo-chunked-v1"


def test_recovery_needs_no_metadata():
    """The sovereign-recovery property: stored bytes + data key -> plaintext."""
    pt = os.urandom(P0 + P + 999)
    obj = b"".join(_encrypt(pt)[0])
    assert v1.is_v1(obj[:8])
    assert _decrypt(obj) == pt


# ── cross-client test vector ────────────────────────────────────────────────
# The browser implementation must reproduce these numbers byte for byte.

def _phrase_data_key(phrase: str) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", phrase).encode(),
                               b"mnemonic", 2048, 64)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"obsideo-phrase-v1/data-key").derive(seed)


def _merkle_root(data: bytes) -> str:
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
    nonce = bytes.fromhex("0000000000000001")
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = _pattern(2 * 1048576 + 12345)

    pieces, header = _encrypt(pt, key=key, nonce=nonce, salt=salt)
    obj = b"".join(pieces)
    assert header.total_chunks == 3
    assert [len(p) for p in pieces] == [1048576, 1048576, 12441]
    assert len(obj) == 2109593
    assert header.pack().hex() == (
        "4f425344010100000000000000000001000102030405060708090a0b0c0d0e0f"
        "00000003000000000000000000000000")
    assert v1.file_key(key, salt).hex() == \
        "2efd38f3f158bddcaf2bcc4ed6feee57cfef09e45ab9a69a6a872ceec51c7c2c"
    assert hashlib.sha256(obj).hexdigest() == \
        "388b301d4843885f4cc377faf537ca92fb3937641b4446b2661f923a8152cfc0"
    assert hashlib.sha256(pieces[0]).hexdigest() == \
        "2a1804321ad136205af4594828353b4fedda5de392f88d73b18f5873446e9e34"
    assert _merkle_root(obj) == (
        "6924b4b6df51624eee35a6a5f7b5131e755ae56ab1fd86a3e3c5b3b2a7beee9b"
        "810b00aaf15aab4a54b6c3620dbb5ae221c7587a3704ee06192686d54fd6dddf")
    assert v1.metadata_for() == {"enc": "obsideo-object-v1"}
    assert _decrypt(obj, key=key, size=len(obj)) == pt
