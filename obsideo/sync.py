"""Sync a local folder with an Obsideo remote prefix (default 'sync/').

Encrypts on push, decrypts on pull (account data key). Tracks state in a local
manifest so unchanged files are skipped. Adapted from Cloud_Terminal's sync onto
the Obsideo storage seam.
"""

import sys
from pathlib import Path

from obsideo_core import config, crypto, storage
from obsideo import manifest

REMOTE_PREFIX = "sync/"


def _sync_dir() -> Path:
    return Path(config.load_config().get("sync_dir", str(Path.home() / "obsideo-sync")))


def ensure_sync_dir() -> Path:
    """Return the sync folder, creating it if needed. Called on login and by every
    sync command so a user never has to make the folder by hand — it just exists."""
    sd = _sync_dir()
    sd.mkdir(parents=True, exist_ok=True)
    return sd


def _remote_key(name: str) -> str:
    return f"{REMOTE_PREFIX}{name}"


def sync_status() -> dict:
    sync_dir = ensure_sync_dir()
    entries = manifest.get_all()
    status = {"to_push": [], "to_pull": [], "synced": []}

    local_files = {f.name: f for f in sync_dir.iterdir() if f.is_file()}

    for name, f in local_files.items():
        local_hash = manifest.file_sha256(f)
        entry = entries.get(name)
        if entry is None or entry.get("local_hash") != local_hash:
            status["to_push"].append(name)
        else:
            status["synced"].append(name)

    # Remote files we know about but don't have locally.
    try:
        remote = storage.list_prefix(REMOTE_PREFIX)
        remote_names = {f["name"] for f in remote["files"]}
    except Exception:
        remote_names = set(entries.keys())
    for name in remote_names:
        if name not in local_files:
            status["to_pull"].append(name)

    return status


def push(verbose: bool = True) -> int:
    sync_dir = ensure_sync_dir()
    files = [p for p in sync_dir.iterdir() if p.is_file()]
    if not files:
        if verbose:
            print(f"  Your sync folder is empty:\n    {sync_dir}\n"
                  f"  Drop files in there, then run `sync push` again.")
        return 0

    do_encrypt = config.load_config().get("encrypt", True)
    entries = manifest.get_all()
    pushed = 0

    for f in files:
        local_hash = manifest.file_sha256(f)
        entry = entries.get(f.name)
        if entry and entry.get("local_hash") == local_hash:
            if verbose:
                print(f"  {f.name} - unchanged, skipping")
            continue

        raw = f.read_bytes()
        body = crypto.encrypt(raw) if do_encrypt else raw
        try:
            key = storage.put(_remote_key(f.name), body)
            manifest.upsert(f.name, remote_key=key, local_hash=local_hash,
                            size=len(raw), encrypted=do_encrypt)
            pushed += 1
            if verbose:
                print(f"  {f.name} - uploaded")
        except Exception as e:
            print(f"  {f.name} - FAILED: {e}", file=sys.stderr)

    return pushed


def pull(verbose: bool = True) -> int:
    sync_dir = ensure_sync_dir()

    try:
        remote = storage.list_prefix(REMOTE_PREFIX)
    except Exception as e:
        print(f"Failed to list remote: {e}", file=sys.stderr)
        return 0

    pulled = 0
    for rf in remote["files"]:
        name = rf["name"]
        local_file = sync_dir / name
        try:
            blob = storage.get(rf["key"])
            try:
                raw = crypto.decrypt(blob)
                encrypted = True
            except Exception:
                raw = blob  # was stored unencrypted
                encrypted = False
            local_file.parent.mkdir(parents=True, exist_ok=True)
            local_file.write_bytes(raw)
            manifest.upsert(name, remote_key=rf["key"],
                            local_hash=manifest.file_sha256(local_file),
                            size=len(raw), encrypted=encrypted)
            pulled += 1
            if verbose:
                print(f"  {name} - downloaded")
        except Exception as e:
            print(f"  {name} - FAILED: {e}", file=sys.stderr)

    return pulled
