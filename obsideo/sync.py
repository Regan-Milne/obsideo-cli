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

# A local guide dropped in the sync folder so a user who opens it knows what it is
# and how to use it. It is NEVER uploaded (push/status skip it).
README_NAME = "READ ME - Obsideo sync.txt"
_README_TEXT = """This is your Obsideo sync folder.

Put files here, then back them up to your encrypted Obsideo storage from the CLI:

    obsideo            open the app
    sync push          upload new / changed files (encrypted on your device)
    sync pull          download your files into this folder
    sync status        see what's pending

Everything is encrypted on your device before it leaves, so Obsideo cannot read
it. In the CLI, type 'about' or 'faq' to learn more.

(This file stays on your computer - it is not uploaded.)
"""


def _sync_dir() -> Path:
    return Path(config.load_config().get("sync_dir", str(Path.home() / "obsideo-sync")))


def ensure_sync_dir() -> Path:
    """Return the sync folder, creating it if needed (and dropping a short READ ME
    the first time). Called on login and by every sync command so a user never has
    to make the folder by hand — it just exists, with instructions inside."""
    sd = _sync_dir()
    created = not sd.exists()
    sd.mkdir(parents=True, exist_ok=True)
    if created:
        try:
            (sd / README_NAME).write_text(_README_TEXT)
        except OSError:
            pass
    return sd


def _remote_key(name: str) -> str:
    return f"{REMOTE_PREFIX}{name}"


def _remote_names() -> tuple[set, bool]:
    """Names actually present under the sync prefix on the remote, and whether we
    could reach it. Used to reconcile against the local manifest — the manifest
    alone can't be trusted (e.g. after switching accounts it still 'remembers'
    files uploaded to the OLD account, which aren't on the new one)."""
    try:
        remote = storage.list_prefix(REMOTE_PREFIX)
        return {f["name"] for f in remote["files"]}, True
    except Exception:
        return set(), False


def sync_status() -> dict:
    sync_dir = ensure_sync_dir()
    entries = manifest.get_all()
    status = {"to_push": [], "to_pull": [], "synced": []}

    local_files = {f.name: f for f in sync_dir.iterdir() if f.is_file() and f.name != README_NAME}
    remote_names, remote_known = _remote_names()

    for name, f in local_files.items():
        local_hash = manifest.file_sha256(f)
        entry = entries.get(name)
        # A file is only "synced" if the manifest matches AND it's really on the
        # remote. If we couldn't reach the remote, fall back to the manifest so a
        # transient outage doesn't flag everything as needing a re-push.
        on_remote = (name in remote_names) if remote_known else True
        if entry is None or entry.get("local_hash") != local_hash or not on_remote:
            status["to_push"].append(name)
        else:
            status["synced"].append(name)

    # Remote files we know about but don't have locally.
    pullable = remote_names if remote_known else set(entries.keys())
    for name in pullable:
        if name not in local_files:
            status["to_pull"].append(name)

    return status


def push(verbose: bool = True) -> int:
    sync_dir = ensure_sync_dir()
    files = [p for p in sync_dir.iterdir() if p.is_file() and p.name != README_NAME]
    if not files:
        if verbose:
            print(f"  Your sync folder is empty:\n    {sync_dir}\n"
                  f"  Drop files in there, then run `sync push` again.")
        return 0

    do_encrypt = config.load_config().get("encrypt", True)
    entries = manifest.get_all()
    # Reconcile against the real remote: only skip a file if the manifest matches
    # AND it's actually up there. This self-heals a stale manifest (e.g. after an
    # account switch, where the manifest still lists files from the old account)
    # without the user having to clear anything.
    remote_names, remote_known = _remote_names()
    pushed = 0

    for f in files:
        local_hash = manifest.file_sha256(f)
        entry = entries.get(f.name)
        on_remote = (f.name in remote_names) if remote_known else True
        if entry and entry.get("local_hash") == local_hash and on_remote:
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
