"""`obsideo recover`: the sovereign-recovery drill. A raw stored object plus
the phrase (or key) becomes the file with no coordinator, gateway or login
involved; anything that does not authenticate writes nothing."""

import hashlib
import os

from obsideo import cli
from obsideo_core import chunked, objectv1, recover as rec

PHRASE = " ".join(["abandon"] * 11 + ["about"])
KEY_HEX = "05d4e219677ac3fdbaa10e86b8ef2598c34edfa31ea8b4f14c670ca0ea8c95e3"


def test_phrase_matches_the_shared_recipe():
    assert rec.data_key_from_phrase(PHRASE).hex() == KEY_HEX
    assert rec.data_key_from_phrase("  " + PHRASE.upper() + "\n").hex() == KEY_HEX
    assert rec.data_key_from_hex("OBSIDEO_DATA_KEY=" + KEY_HEX).hex() == KEY_HEX


def _write_v1(path, data, key=bytes.fromhex(KEY_HEX)):
    pieces, _ = objectv1.encrypt(key, data)
    path.write_bytes(b"".join(pieces))


def test_recover_v1_with_phrase_offline(tmp_path, capsys):
    data = os.urandom(objectv1.P0 + 5000)
    stored = tmp_path / "blob.bin"
    _write_v1(stored, data)
    out = tmp_path / "photo.jpg"
    rc = cli.run_recover([str(stored), str(out), "--phrase", PHRASE])
    assert rc == 0
    assert out.read_bytes() == data
    assert "Recovered" in capsys.readouterr().out
    assert list(tmp_path.glob(".*partial")) == []


def test_recover_v1_with_key_hex(tmp_path):
    data = b"tiny"
    stored = tmp_path / "blob.bin"
    _write_v1(stored, data)
    out = tmp_path / "t.txt"
    assert cli.run_recover([str(stored), str(out), "--key=" + KEY_HEX]) == 0
    assert out.read_bytes() == data


def test_recover_single_stream(tmp_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes.fromhex(KEY_HEX)
    nonce = os.urandom(12)
    stored = tmp_path / "old.bin"
    stored.write_bytes(nonce + AESGCM(key).encrypt(nonce, b"legacy bytes", None))
    out = tmp_path / "old.txt"
    assert cli.run_recover([str(stored), str(out), "--key", KEY_HEX]) == 0
    assert out.read_bytes() == b"legacy bytes"


def test_wrong_key_writes_nothing(tmp_path, capsys):
    stored = tmp_path / "blob.bin"
    _write_v1(stored, b"secret")
    out = tmp_path / "s.txt"
    rc = cli.run_recover([str(stored), str(out), "--key", "00" * 32])
    assert rc == 1
    assert not out.exists()
    assert list(tmp_path.glob(".*partial")) == []
    assert "does not open" in capsys.readouterr().out


def test_damaged_later_chunk_writes_nothing(tmp_path):
    data = os.urandom(objectv1.P0 + objectv1.P + 9)
    stored = tmp_path / "blob.bin"
    _write_v1(stored, data)
    b = bytearray(stored.read_bytes())
    b[objectv1.MERKLE + 7] ^= 1
    stored.write_bytes(bytes(b))
    out = tmp_path / "d.bin"
    assert cli.run_recover([str(stored), str(out), "--key", KEY_HEX]) == 1
    assert not out.exists()


def test_chunked_v1_is_refused_with_the_reason(tmp_path, capsys):
    key = bytes.fromhex(KEY_HEX)
    it, _ = chunked.encrypt_chunked(key, b"needs its nonce", bytes(8))
    stored = tmp_path / "chunked.bin"
    stored.write_bytes(b"".join(it))
    out = tmp_path / "c.txt"
    assert cli.run_recover([str(stored), str(out), "--key", KEY_HEX]) == 1
    assert not out.exists()
    assert "chunked-v1" in capsys.readouterr().out


def test_usage_errors(tmp_path, capsys):
    assert cli.run_recover([]) == 2
    assert cli.run_recover(["a", "b", "--key", "zz", "--phrase", PHRASE]) == 2
    assert cli.run_recover(["--help"]) == 0
    assert "Usage: obsideo recover" in capsys.readouterr().out
    assert cli.run_recover(["a", "b", "--phrase", "only three words"]) == 1
    assert "12 words" in capsys.readouterr().out


def test_vector_object_recovers(tmp_path):
    """The cross-client vector's object, as a file on disk, comes back."""
    key = bytes.fromhex(KEY_HEX)
    pt = bytes(k % 256 for k in range(2 * 1048576 + 12345))
    pieces, _ = objectv1.encrypt(key, pt, file_nonce=bytes.fromhex("0000000000000001"),
                                 key_salt=bytes(range(16)))
    obj = b"".join(pieces)
    assert hashlib.sha256(obj).hexdigest() == \
        "388b301d4843885f4cc377faf537ca92fb3937641b4446b2661f923a8152cfc0"
    stored = tmp_path / "vector.bin"
    stored.write_bytes(obj)
    out = tmp_path / "vector.out"
    assert cli.run_recover([str(stored), str(out), "--phrase", PHRASE]) == 0
    assert out.read_bytes() == pt
