"""Core tests: crypto round-trip + S3 list parsing (mocked client)."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Isolate config dir so tests never touch ~/.obsideo.
os.environ["OBSIDEO_DATA_KEY"] = os.urandom(32).hex()

from obsideo_core import crypto, storage


def test_crypto_round_trip():
    data = os.urandom(4096)
    blob = crypto.encrypt(data)
    assert blob[:12] != data[:12]  # nonce prepended, not plaintext
    assert crypto.decrypt(blob) == data


def test_crypto_wrong_key_fails():
    blob = crypto.encrypt(b"secret")
    other = os.urandom(32).hex()
    with mock.patch.dict(os.environ, {"OBSIDEO_DATA_KEY": other}):
        with pytest.raises(Exception):
            crypto.decrypt(blob)


@pytest.fixture()
def s3_creds(monkeypatch):
    monkeypatch.setenv("OBSIDEO_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("OBSIDEO_S3_SECRET_KEY", "secret")
    monkeypatch.setenv("OBSIDEO_S3_BUCKET", "obsideo")
    storage.reset_client()
    yield
    storage.reset_client()


def test_list_prefix_parses_folders_and_files(s3_creds, monkeypatch):
    monkeypatch.setattr(storage, "_names_on", lambda: False)  # plain keys for this test
    fake = mock.MagicMock()
    fake.list_objects_v2.return_value = {
        "CommonPrefixes": [{"Prefix": "docs/"}, {"Prefix": "photos/"}],
        "Contents": [
            {"Key": "readme.txt", "Size": 12},
            {"Key": "note.md", "Size": 40},
            {"Key": "", "Size": 0},  # folder marker for root - skipped
        ],
        "IsTruncated": False,
    }
    monkeypatch.setattr(storage, "_s3", lambda: fake)

    out = storage.list_prefix("")
    assert out["folders"] == ["docs", "photos"]
    names = [f["name"] for f in out["files"]]
    assert names == ["note.md", "readme.txt"]  # sorted


def test_get_uses_full_object_get(s3_creds, monkeypatch):
    monkeypatch.setattr(storage, "_names_on", lambda: False)  # check exact plain key
    fake = mock.MagicMock()
    body = mock.MagicMock(); body.read.return_value = b"ciphertext"
    fake.get_object.return_value = {"Body": body}
    monkeypatch.setattr(storage, "_s3", lambda: fake)

    assert storage.get("k") == b"ciphertext"
    fake.get_object.assert_called_once_with(Bucket="obsideo", Key="k")
    assert not fake.download_file.called  # never ranged


# ── filename encryption (Level 1 metadata privacy) ──────────────────────────

def test_name_encryption_round_trip():
    from obsideo_core import names
    tok = names.encrypt_name("my secret folder")
    assert tok != "my secret folder"
    assert "/" not in tok  # safe as a single path component
    assert names.decrypt_name(tok) == "my secret folder"


def test_name_encryption_is_deterministic():
    from obsideo_core import names
    # Deterministic so server-side prefix listing works.
    assert names.encrypt_name("photos") == names.encrypt_name("photos")


def test_encrypt_path_per_component():
    from obsideo_core import names
    enc = names.encrypt_path("a/b/c.txt")
    segs = enc.split("/")
    assert len(segs) == 3  # structure preserved (3 components)
    # Each component is hidden (token != plaintext) yet round-trips back. Compare
    # per-segment rather than substring-scanning the whole path: a 1-char name
    # like "a" appears by chance inside base64 tokens, which made this flaky.
    for plain, tok in zip(["a", "b", "c.txt"], segs):
        assert tok != plain
        assert names.decrypt_name(tok) == plain


def test_storage_stores_under_encrypted_key(s3_creds, monkeypatch):
    fake = mock.MagicMock()
    monkeypatch.setattr(storage, "_s3", lambda: fake)
    monkeypatch.setattr(storage, "ensure_bucket", lambda: None)
    storage.put("docs/secret.txt", b"x")  # names ON by default
    _, args, kwargs = fake.mock_calls[0]
    stored_key = args[2]
    assert "secret.txt" not in stored_key and "docs" not in stored_key


def test_list_prefix_decrypts_names_roundtrip(s3_creds, monkeypatch):
    """Store under encrypted keys, then list and confirm real names come back."""
    from obsideo_core import names
    enc_prefix = names.encrypt_path("vault") + "/"
    enc_file = enc_prefix + names.encrypt_name("passwords.txt")
    enc_sub = enc_prefix + names.encrypt_name("sub") + "/"

    fake = mock.MagicMock()
    fake.list_objects_v2.return_value = {
        "CommonPrefixes": [{"Prefix": enc_sub}],
        "Contents": [{"Key": enc_file, "Size": 99}],
        "IsTruncated": False,
    }
    monkeypatch.setattr(storage, "_s3", lambda: fake)

    out = storage.list_prefix("vault")
    assert out["folders"] == ["sub"]
    assert out["files"][0]["name"] == "passwords.txt"
    assert out["files"][0]["key"] == "vault/passwords.txt"  # real path for re-fetch


# ── login: referral code threading ────────────────────────────────────────────

def test_verify_includes_referral_code_when_given(monkeypatch):
    from obsideo_core import login, identity, config
    sent = {}
    monkeypatch.setattr(login, "_post_json", lambda url, payload: sent.update(payload) or {"access_key": "AKIA", "secret_key": "s"})
    monkeypatch.setattr(identity, "get_or_create_signing_pubkey", lambda: "obk_sig_" + "A" * 43)
    monkeypatch.setattr(config, "write_credentials", lambda creds: None)

    login.verify("a@b.com", "123456", url="http://x", referral_code="ABCD234")
    assert sent["referral_code"] == "ABCD234"


def test_verify_omits_referral_code_when_blank(monkeypatch):
    from obsideo_core import login, identity, config
    sent = {}
    monkeypatch.setattr(login, "_post_json", lambda url, payload: sent.update(payload) or {"access_key": "AKIA", "secret_key": "s"})
    monkeypatch.setattr(identity, "get_or_create_signing_pubkey", lambda: "obk_sig_" + "A" * 43)
    monkeypatch.setattr(config, "write_credentials", lambda creds: None)

    login.verify("a@b.com", "123456", url="http://x")
    assert "referral_code" not in sent  # never send an empty/None code


# ── New-credential propagation retry ─────────────────────────────────────────
# A freshly issued key is unknown to the gateway until its next credential
# refresh, so the first call after signup can 403 while nothing is wrong.

def _client_error(code, status=403):
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "PutObject",
    )


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(storage.time, "sleep", lambda s: None)
    monkeypatch.setattr(storage, "propagation_notifier", None)  # quiet by default


@pytest.fixture
def fresh_credentials(monkeypatch):
    monkeypatch.setattr(storage, "_credentials_are_fresh", lambda: True)


def test_retries_propagation_error_then_succeeds(no_sleep, fresh_credentials):
    calls = []

    def op():
        calls.append(1)
        if len(calls) < 3:
            raise _client_error("InvalidAccessKeyId")
        return "uploaded"

    assert storage.with_propagation_retry(op) == "uploaded"
    assert len(calls) == 3


def test_notifier_fires_once(no_sleep, fresh_credentials, monkeypatch):
    seen = []
    monkeypatch.setattr(storage, "propagation_notifier", lambda: seen.append(1))
    calls = []

    def op():
        calls.append(1)
        if len(calls) < 4:
            raise _client_error("NoSuchBucket")
        return "ok"

    storage.with_propagation_retry(op)
    assert seen == [1]  # said once, not once per retry


def test_established_account_fails_fast(no_sleep, monkeypatch):
    """Same error on an old account means a revoked key, not propagation.
    Retrying for a minute there would hide a real failure behind a hang."""
    monkeypatch.setattr(storage, "_credentials_are_fresh", lambda: False)
    calls = []

    def op():
        calls.append(1)
        raise _client_error("InvalidAccessKeyId")

    with pytest.raises(Exception):
        storage.with_propagation_retry(op)
    assert len(calls) == 1  # no retry


def test_non_propagation_error_is_not_retried(no_sleep, fresh_credentials):
    calls = []

    def op():
        calls.append(1)
        raise _client_error("SignatureDoesNotMatch", status=400)

    with pytest.raises(Exception):
        storage.with_propagation_retry(op)
    assert len(calls) == 1


def test_gives_up_at_the_deadline(no_sleep, fresh_credentials):
    """A key that never propagates must surface the real error, not loop."""
    calls = []

    def op():
        calls.append(1)
        raise _client_error("AccessDenied")

    with pytest.raises(Exception):
        storage.with_propagation_retry(op)
    assert 1 < len(calls) <= len(storage._PROPAGATION_BACKOFF) + 1
