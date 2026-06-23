"""Obsideo storage seam — S3 to the Obsideo gateway (external passthrough).

The gateway stores bytes verbatim and holds no keys; the client encrypts before
calling here (see crypto.py), so the gateway/coord/providers see ciphertext only
(Principle 1). Objects land on three independent providers (RF=3) via the coord.

This is the shared core both the general `obsideo` CLI and the `mlvault` extension
build on. It generalizes the original mlvault seam with the browse operations a
file manager needs: list (prefix + delimiter), delete, head, mkdir-marker.

Gateway constraints engineered around:
  * No HTTP Range — downloads use a single full-object GET (never
    download_file/download_fileobj, which issue ranged multipart GETs).
  * Path-style only; SigV4; ListObjectsV2 only.
  * Uploads may be multipart (PUT parts, no Range).
"""

import os
from pathlib import Path

from obsideo_core import config

_DEFAULT_ENDPOINT = "https://s3.obsideo.io"
_DEFAULT_REGION = "us-east-1"
_MULTIPART_CHUNK = 16 * 1024 * 1024  # 16 MiB
# The gateway rejects empty-body PUTs, so empty folders are marked with a tiny
# non-empty placeholder object rather than a zero-byte key.
_FOLDER_MARKER = ".keep"


def _names_on() -> bool:
    return config.load_config().get("encrypt_names", True)


def _skey(key: str) -> str:
    """Map a real path key to the on-server storage key — encrypts each path
    component when name-encryption is on, so Obsideo never sees real names."""
    if not key or not _names_on():
        return key
    from obsideo_core import names
    return names.encrypt_path(key)


class StorageConfigError(EnvironmentError):
    """Raised when Obsideo credentials are missing/incomplete."""


def _endpoint() -> str:
    return os.environ.get("OBSIDEO_S3_ENDPOINT", _DEFAULT_ENDPOINT)


def _region() -> str:
    return os.environ.get("OBSIDEO_S3_REGION", _DEFAULT_REGION)


def bucket() -> str:
    return os.environ.get("OBSIDEO_S3_BUCKET") or config.load_config().get("bucket", "obsideo")


def _require_credentials() -> tuple[str, str]:
    ak = os.environ.get("OBSIDEO_S3_ACCESS_KEY")
    sk = os.environ.get("OBSIDEO_S3_SECRET_KEY")
    if not ak or not sk:
        raise StorageConfigError(
            "You're not logged in. Run `obsideo login` to get started (5 GB... "
            "actually 3 GB free), or set OBSIDEO_S3_ACCESS_KEY / OBSIDEO_S3_SECRET_KEY."
        )
    return ak, sk


_client = None


def _s3():
    global _client
    if _client is not None:
        return _client
    try:
        import boto3
        from botocore.config import Config
    except ImportError as e:  # pragma: no cover
        raise StorageConfigError("boto3 is required. pip install boto3") from e

    ak, sk = _require_credentials()
    base = dict(
        region_name=_region(),
        signature_version="s3v4",
        s3={"addressing_style": "path"},
        retries={"max_attempts": 3, "mode": "standard"},
    )
    # boto3 >=1.36 adds CRC32 checksum trailers by default, which the passthrough
    # gateway doesn't validate and which break SigV4. Pin to when_required where
    # supported; older botocore lacks the params (and the problematic default).
    try:
        cfg = Config(request_checksum_calculation="when_required",
                     response_checksum_validation="when_required", **base)
    except TypeError:
        cfg = Config(**base)

    _client = boto3.client("s3", endpoint_url=_endpoint(),
                           aws_access_key_id=ak, aws_secret_access_key=sk, config=cfg)
    return _client


def reset_client() -> None:
    """Drop the cached client (e.g. after login swaps credentials)."""
    global _client
    _client = None


def ensure_bucket() -> None:
    from botocore.exceptions import ClientError
    s3, b = _s3(), bucket()
    try:
        s3.head_bucket(Bucket=b)
        return
    except ClientError:
        pass
    try:
        s3.create_bucket(Bucket=b)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


# ── Object ops ──────────────────────────────────────────────────────────────

def put(key: str, data: bytes) -> str:
    """Upload bytes to key. Returns the key."""
    import io
    from boto3.s3.transfer import TransferConfig
    s3 = _s3()
    ensure_bucket()
    transfer = TransferConfig(multipart_threshold=_MULTIPART_CHUNK,
                              multipart_chunksize=_MULTIPART_CHUNK)
    s3.upload_fileobj(io.BytesIO(data), bucket(), _skey(key), Config=transfer)
    return key


def upload_file(local_path: Path, key: str) -> str:
    from boto3.s3.transfer import TransferConfig
    s3 = _s3()
    ensure_bucket()
    transfer = TransferConfig(multipart_threshold=_MULTIPART_CHUNK,
                              multipart_chunksize=_MULTIPART_CHUNK)
    with open(local_path, "rb") as f:
        s3.upload_fileobj(f, bucket(), _skey(key), Config=transfer)
    return key


def get(key: str) -> bytes:
    """Download an object by key (single full-object GET — no Range)."""
    from botocore.exceptions import ClientError
    try:
        resp = _s3().get_object(Bucket=bucket(), Key=_skey(key))
        return resp["Body"].read()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NoSuchBucket"):
            raise FileNotFoundError(f"Not found: {key}") from e
        raise RuntimeError(f"Download failed for '{key}': {e}") from e


def download_file(key: str, local_path: Path) -> None:
    data = get(key)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)


def delete(key: str) -> None:
    _s3().delete_object(Bucket=bucket(), Key=_skey(key))


def head(key: str) -> dict | None:
    """Return {'size','last_modified'} or None if absent."""
    from botocore.exceptions import ClientError
    try:
        h = _s3().head_object(Bucket=bucket(), Key=_skey(key))
        return {"size": h.get("ContentLength"), "last_modified": h.get("LastModified")}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchKey", "NotFound"):
            return None
        raise


def exists(key: str) -> bool:
    return head(key) is not None


def total_usage() -> tuple[int, int]:
    """Total stored bytes + object count across the account's bucket (flat list).
    Lets `account` show real usage without the signup-service token — it just reads
    the storage the account can already see. Names stay opaque; only sizes summed."""
    s3 = _s3()
    total = 0
    count = 0
    token = None
    while True:
        kwargs = dict(Bucket=bucket())
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            if obj["Key"].endswith("/"):
                continue  # folder marker, not a real object
            total += obj.get("Size", 0)
            count += 1
        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break
    return total, count


def list_prefix(prefix: str = "", delimiter: str = "/") -> dict:
    """List one VFS level. Returns {'folders': [name...], 'files': [{name,key,size}]}.

    With delimiter='/', S3 returns CommonPrefixes (folders) + Contents at this
    level. Folder-marker objects (keys ending in '/') are hidden from files.
    """
    s3 = _s3()
    on = _names_on()
    norm = prefix
    if norm and not norm.endswith("/"):
        norm += "/"

    # The server query runs against the ENCRYPTED prefix; the returned tokens are
    # decrypted back to real names for display. Returned `key` is the REAL path so
    # callers (get/rm/cd) can re-encrypt it transparently.
    if on and norm:
        from obsideo_core import names
        enc_prefix = names.encrypt_path(norm) + "/"
    else:
        enc_prefix = norm

    def _name(token: str) -> str:
        if not on:
            return token
        from obsideo_core import names
        return names.safe_decrypt_name(token)[0]

    folders, files = [], []
    token = None
    while True:
        kwargs = dict(Bucket=bucket(), Prefix=enc_prefix, Delimiter=delimiter)
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)

        for cp in resp.get("CommonPrefixes", []):
            enc_name = cp["Prefix"][len(enc_prefix):].rstrip("/")
            if enc_name:
                folders.append(_name(enc_name))

        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if key == enc_prefix or key.endswith("/"):
                continue  # the folder marker itself
            name = _name(key[len(enc_prefix):])
            if name == _FOLDER_MARKER:
                continue  # hide the .keep placeholder that makes empty folders visible
            files.append({"name": name, "key": norm + name, "size": obj.get("Size", 0)})

        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break

    folders.sort()
    files.sort(key=lambda f: f["name"])
    return {"folders": folders, "files": files}


def mkdir(prefix: str) -> str:
    """Make an empty folder visible in `ls`. S3 has no real directories; we
    write a tiny placeholder at 'prefix/.keep' (the gateway rejects empty
    bodies, so the marker is non-empty). It's hidden from listings."""
    norm = prefix if prefix.endswith("/") else prefix + "/"
    put(norm + _FOLDER_MARKER, b".obsideo\n")
    return norm


def verify_pop(key: str) -> dict:
    """Confirm an object is stored + report durability posture (RF=3)."""
    h = head(key)
    if h is None:
        return {"stored": False, "size_bytes": None, "replication_factor": 3, "backend": "obsideo"}
    return {"stored": True, "size_bytes": h["size"], "replication_factor": 3, "backend": "obsideo"}
