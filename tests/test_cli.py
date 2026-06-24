"""CLI shell test: put -> ls -> get -> rm round-trip against in-memory storage,
with real client-side encryption in the path."""

import os
from pathlib import Path
from unittest import mock

import pytest

os.environ.setdefault("OBSIDEO_DATA_KEY", os.urandom(32).hex())
os.environ["OBSIDEO_S3_ACCESS_KEY"] = "AKIATEST"
os.environ["OBSIDEO_S3_SECRET_KEY"] = "secret"

from obsideo import cli
from obsideo_core import storage, crypto


class FakeStore:
    """In-memory object store standing in for the Obsideo gateway."""
    def __init__(self):
        self.objs = {}

    def put(self, key, data):
        self.objs[key] = data
        return key

    def get(self, key):
        if key not in self.objs:
            raise FileNotFoundError(key)
        return self.objs[key]

    def delete(self, key):
        self.objs.pop(key, None)

    def list_prefix(self, prefix="", delimiter="/"):
        norm = prefix if (not prefix or prefix.endswith("/")) else prefix + "/"
        folders, files = set(), []
        for k in self.objs:
            if not k.startswith(norm):
                continue
            rest = k[len(norm):]
            if "/" in rest:
                folders.add(rest.split("/", 1)[0])
            elif rest and not k.endswith("/"):
                files.append({"name": rest, "key": k, "size": len(self.objs[k])})
        return {"folders": sorted(folders), "files": sorted(files, key=lambda f: f["name"])}

    def head(self, key):
        return {"size": len(self.objs[key]), "last_modified": None} if key in self.objs else None


@pytest.fixture()
def shell(monkeypatch, tmp_path):
    fake = FakeStore()
    monkeypatch.setattr(storage, "put", fake.put)
    monkeypatch.setattr(storage, "get", fake.get)
    monkeypatch.setattr(storage, "delete", fake.delete)
    monkeypatch.setattr(storage, "list_prefix", fake.list_prefix)
    monkeypatch.setattr(storage, "head", fake.head)
    return cli.ObsideoShell(), fake, tmp_path


def test_put_get_roundtrip_encrypted(shell, capsys):
    sh, fake, tmp = shell
    src = tmp / "secret.txt"
    src.write_bytes(b"my private notes")

    sh.do_put(str(src))
    # Stored object is ciphertext, not plaintext.
    assert b"my private notes" not in next(iter(fake.objs.values()))

    out = tmp / "restored.txt"
    sh.do_get(f"secret.txt {out}")
    assert out.read_bytes() == b"my private notes"


def test_ls_shows_files_and_folders(shell, capsys):
    sh, fake, tmp = shell
    fake.objs["a.txt"] = crypto.encrypt(b"a")
    fake.objs["docs/b.txt"] = crypto.encrypt(b"b")
    sh.do_ls("")
    out = capsys.readouterr().out
    assert "[dir]  docs/" in out
    assert "[file] a.txt" in out


def test_cd_pwd(shell, capsys):
    sh, _, _ = shell
    sh.do_cd("docs")
    assert sh._cwd == "docs/"
    sh.do_cd("sub")
    assert sh._cwd == "docs/sub/"
    sh.do_cd("..")
    assert sh._cwd == "docs/"
    sh.do_cd("/")
    assert sh._cwd == ""


def test_rm(shell):
    sh, fake, tmp = shell
    fake.objs["gone.txt"] = b"x"
    sh.do_rm("gone.txt")
    assert "gone.txt" not in fake.objs


def test_put_into_subdir(shell, tmp_path):
    sh, fake, tmp = shell
    src = tmp / "f.bin"; src.write_bytes(b"data")
    sh.do_cd("projects")
    sh.do_put(str(src))
    assert "projects/f.bin" in fake.objs


def test_tokenizer_handles_quoted_spaced_windows_paths():
    from obsideo.cli import _tokens, _unquote
    # Quoted Windows path with spaces stays one token, quotes stripped, backslashes kept.
    assert _tokens(r'"C:\a b\Screenshot 1.png"') == [r"C:\a b\Screenshot 1.png"]
    assert _tokens(r'"C:\a b\f.png" rename.png') == [r"C:\a b\f.png", "rename.png"]
    assert _unquote('"my file.txt"') == "my file.txt"
    assert _unquote("plain.txt") == "plain.txt"


def test_put_quoted_spaced_path(shell, tmp_path):
    sh, fake, tmp = shell
    src = tmp / "my report.txt"
    src.write_bytes(b"hello")
    sh.do_put(f'"{src}"')
    assert "my report.txt" in fake.objs


def test_put_folder_recursive(shell, tmp_path):
    sh, fake, tmp = shell
    folder = tmp / "photos"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.jpg").write_bytes(b"aaa")
    (folder / "b.txt").write_bytes(b"bbb")
    (folder / "sub" / "c.bin").write_bytes(b"ccc")

    sh.do_put(str(folder))

    # Structure preserved under photos/, all three files uploaded (encrypted).
    assert set(fake.objs.keys()) == {"photos/a.jpg", "photos/b.txt", "photos/sub/c.bin"}
    assert b"aaa" not in fake.objs["photos/a.jpg"]  # ciphertext, not plaintext


def test_put_folder_into_cwd(shell, tmp_path):
    sh, fake, tmp = shell
    folder = tmp / "docs"
    folder.mkdir()
    (folder / "x.txt").write_bytes(b"x")
    sh.do_cd("backup")
    sh.do_put(str(folder))
    assert "backup/docs/x.txt" in fake.objs


# ── Banner + update check (0.2.1) ─────────────────────────────────────────────

def test_banner_tty_gated_once(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("OBSIDEO_NO_BANNER", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    cli._BANNER_SHOWN = False
    cli.show_banner()
    assert "OBSIDEO DRIVE" in capsys.readouterr().err
    cli.show_banner()  # once per process
    assert capsys.readouterr().err == ""
    # non-tty: silent
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False, raising=False)
    cli._BANNER_SHOWN = False
    cli.show_banner()
    assert capsys.readouterr().err == ""


def test_parse_version_ordering():
    assert cli._parse_version("0.2.10") > cli._parse_version("0.2.9")
    assert cli._parse_version("0.3.0") > cli._parse_version("0.2.99")
    assert cli._parse_version("0.2.1") == cli._parse_version("0.2.1")
    assert not (cli._parse_version("0.2.0") > cli._parse_version("0.2.1"))


def test_update_check_silent_when_not_tty(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False, raising=False)
    called = []
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda: called.append(1) or "9.9.9")
    cli.check_for_update()
    assert capsys.readouterr().err == ""
    assert called == []  # short-circuits before any network call


def test_update_check_noop_when_current(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("OBSIDEO_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(cli.config, "VERSION", "0.2.1")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda: "0.2.1")  # not newer
    asked = []
    monkeypatch.setattr("builtins.input", lambda *a: asked.append(1) or "y")
    cli.check_for_update()
    assert asked == []  # never prompts when already current
    assert "Update available" not in capsys.readouterr().err


def test_update_check_prompts_and_respects_no(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("OBSIDEO_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(cli.config, "VERSION", "0.2.1")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda: "0.2.2")
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    ran = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: ran.append(a))
    cli.check_for_update()
    err = capsys.readouterr().err
    assert "Update available: 0.2.1 -> 0.2.2" in err
    assert ran == []  # declined -> no pip invocation


def test_update_check_runs_pip_on_yes_posix(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys, "platform", "linux")  # in-process upgrade path
    monkeypatch.delenv("OBSIDEO_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(cli.config, "VERSION", "0.2.1")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda: "0.2.2")
    monkeypatch.setattr("builtins.input", lambda *a: "y")

    class _R:
        returncode = 0
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: calls.append(a[0]) or _R())
    with pytest.raises(SystemExit) as e:
        cli.check_for_update()
    assert e.value.code == 0
    assert calls and calls[0][1:] == ["-m", "pip", "install", "-U", "--no-cache-dir", "obsideo-cli"]


def test_update_check_windows_prints_command_not_pip(monkeypatch, capsys):
    # On Windows the running .exe is locked; "yes" must NOT run pip in-process,
    # it prints the command instead (no WinError 32, no doomed self-replace).
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.delenv("OBSIDEO_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(cli.config, "VERSION", "0.2.1")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda: "0.2.2")
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    ran = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: ran.append(a))
    cli.check_for_update()  # returns, does not SystemExit
    err = capsys.readouterr().err
    assert ran == []  # never attempts the locked self-replace
    assert "pip install -U --no-cache-dir obsideo-cli" in err


# ── sync auto-setup + info commands (0.2.6) ───────────────────────────────────

def test_ensure_sync_dir_creates(tmp_path, monkeypatch):
    from obsideo import sync
    target = tmp_path / "mysync"
    monkeypatch.setattr(sync, "_sync_dir", lambda: target)
    assert not target.exists()
    sd = sync.ensure_sync_dir()
    assert sd == target and target.is_dir()  # auto-created, no manual mkdir


def test_push_empty_folder_is_friendly_noop(tmp_path, monkeypatch, capsys):
    from obsideo import sync
    monkeypatch.setattr(sync, "_sync_dir", lambda: tmp_path / "s")
    n = sync.push(verbose=True)
    assert n == 0
    out = capsys.readouterr().out.lower()
    assert "empty" in out and "sync push" in out  # guides instead of erroring


def test_about_and_faq_print(capsys):
    sh = cli.ObsideoShell()
    sh.do_about("")
    sh.do_faq("")
    out = capsys.readouterr().out
    assert "OBSIDEO DRIVE" in out and "FAQ" in out and "obsideo-sync" in out


def test_messages_handles_unreachable(monkeypatch, capsys):
    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(cli.urllib.request, "urlopen", boom)
    cli.ObsideoShell().do_messages("")
    assert "couldn't reach" in capsys.readouterr().out.lower()


def test_sync_push_reuploads_when_remote_missing(tmp_path, monkeypatch, capsys):
    # Stale manifest (e.g. after an account switch) says a file is synced, but the
    # remote is actually empty -> push must RE-UPLOAD, not skip. Regression for the
    # "unchanged, skipping" + empty-remote bug after re-login to a new account.
    from obsideo import sync, manifest
    sd = tmp_path / "obsideo-sync"
    monkeypatch.setattr(sync, "_sync_dir", lambda: sd)
    sync.ensure_sync_dir()
    f = sd / "a.txt"; f.write_bytes(b"hello")
    h = manifest.file_sha256(f)
    monkeypatch.setattr(manifest, "get_all", lambda: {"a.txt": {"local_hash": h}})
    monkeypatch.setattr(manifest, "upsert", lambda *a, **k: None)
    monkeypatch.setattr(cli.storage, "list_prefix", lambda prefix: {"folders": [], "files": []})
    put = []
    monkeypatch.setattr(cli.storage, "put", lambda key, body: put.append(key) or key)
    n = sync.push(verbose=True)
    assert n == 1 and put and "a.txt" in put[0]
    assert "uploaded" in capsys.readouterr().out


def test_sync_push_skips_when_present_and_unchanged(tmp_path, monkeypatch, capsys):
    # The optimization still holds: a file that's genuinely unchanged AND present
    # on the remote is skipped (no needless re-upload).
    from obsideo import sync, manifest
    sd = tmp_path / "obsideo-sync"
    monkeypatch.setattr(sync, "_sync_dir", lambda: sd)
    sync.ensure_sync_dir()
    f = sd / "a.txt"; f.write_bytes(b"hello")
    h = manifest.file_sha256(f)
    monkeypatch.setattr(manifest, "get_all", lambda: {"a.txt": {"local_hash": h}})
    monkeypatch.setattr(cli.storage, "list_prefix",
                        lambda prefix: {"folders": [], "files": [{"name": "a.txt", "key": "sync/a.txt", "size": 5}]})
    put = []
    monkeypatch.setattr(cli.storage, "put", lambda key, body: put.append(key) or key)
    n = sync.push(verbose=True)
    assert n == 0 and put == []
    assert "skipping" in capsys.readouterr().out


def test_sync_readme_created_and_not_pushed(tmp_path, monkeypatch, capsys):
    from obsideo import sync
    sd = tmp_path / "obsideo-sync"
    monkeypatch.setattr(sync, "_sync_dir", lambda: sd)
    sync.ensure_sync_dir()
    readme = sd / sync.README_NAME
    assert readme.exists() and "sync push" in readme.read_text()  # guide dropped in
    # A folder containing ONLY the README is treated as empty (README never uploads).
    n = sync.push(verbose=True)
    assert n == 0
    assert "empty" in capsys.readouterr().out.lower()


def test_account_computes_usage_without_token(monkeypatch, tmp_path, capsys):
    # No gateway info + no signup token -> compute from storage, NOT nag to log in.
    from obsideo import sync
    monkeypatch.setattr(cli, "_fetch_account_info", lambda: None)  # don't hit network
    monkeypatch.setattr(cli.config, "account_token", lambda: None)
    monkeypatch.setattr(cli.storage, "total_usage", lambda: (1_500_000, 7))
    monkeypatch.setattr(cli.storage, "bucket", lambda: "tb")
    monkeypatch.setattr(sync, "_sync_dir", lambda: tmp_path / "s")
    cli.ObsideoShell().do_account("")
    out = capsys.readouterr().out
    assert "across 7 file" in out
    assert "obsideo login" not in out and "sign in" not in out.lower()


def test_account_shows_percentage_from_gateway(monkeypatch, tmp_path, capsys):
    # When the gateway returns quota, account shows used / quota / % + a bar.
    from obsideo import sync
    monkeypatch.setattr(cli, "_fetch_account_info",
                        lambda: {"tier": "testdrive", "used_bytes": 500_000_000,
                                 "quota_bytes": 5_368_709_120, "object_count": 314})
    monkeypatch.setattr(cli.storage, "bucket", lambda: "obsideo")
    monkeypatch.setattr(sync, "_sync_dir", lambda: tmp_path / "s")
    cli.ObsideoShell().do_account("")
    out = capsys.readouterr().out
    assert "/" in out and "%" in out and "[" in out  # used / quota (pct) + bar
    assert "314 object" in out and "Free" in out  # testdrive shown as Free


def test_precmd_strips_obsideo_prefix():
    sh = cli.ObsideoShell()
    assert sh.precmd("obsideo ls") == "ls"
    assert sh.precmd("obsideo login") == "login"
    assert sh.precmd("ls") == "ls"  # unchanged when no prefix


# ── referral program ──────────────────────────────────────────────────────────

def test_gb_formats_cleanly():
    assert cli._gb(2.0) == "2" and cli._gb(2) == "2"
    assert cli._gb(2.5) == "2.5"
    assert cli._gb(0) == "0"


def test_refer_shows_code_and_stats(monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "account_token", lambda: "obt_x")
    monkeypatch.setattr(cli, "_fetch_referral", lambda: {
        "code": "ABCD234", "invited": 2, "active": 1, "pending": 1,
        "earned_gb": 2.0, "newly_credited": 1, "owner_bonus_gb_each": 2,
        "redeemer_bonus_gb": 1, "quota_gb": 5.0,
    })
    cli.ObsideoShell().do_refer("")
    out = capsys.readouterr().out
    assert "ABCD234" in out
    assert "Invited: 2" in out and "Active: 1" in out
    assert "+2 GB earned" not in out  # that phrasing is the account line, not refer
    assert "just activated" in out  # newly_credited celebration
    assert "reserves the right" in out  # disclaimer present


def test_refer_without_token_guides_to_login(monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "account_token", lambda: None)
    cli.ObsideoShell().do_refer("")
    out = capsys.readouterr().out.lower()
    assert "login" in out and "email" in out


def test_refer_handles_unreachable_service(monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "account_token", lambda: "obt_x")
    monkeypatch.setattr(cli, "_fetch_referral", lambda: None)
    cli.ObsideoShell().do_refer("")
    assert "couldn't load" in capsys.readouterr().out.lower()


def test_account_shows_referral_line(monkeypatch, tmp_path, capsys):
    from obsideo import sync
    monkeypatch.setattr(cli, "_fetch_account_info",
                        lambda: {"tier": "promo", "used_bytes": 1, "quota_bytes": 5_368_709_120})
    monkeypatch.setattr(cli.config, "account_token", lambda: "obt_x")
    monkeypatch.setattr(cli, "_fetch_referral",
                        lambda: {"code": "ABCD234", "active": 2, "earned_gb": 4.0})
    monkeypatch.setattr(cli.storage, "bucket", lambda: "obsideo")
    monkeypatch.setattr(sync, "_sync_dir", lambda: tmp_path / "s")
    cli.ObsideoShell().do_account("")
    out = capsys.readouterr().out
    assert "Referrals: code ABCD234" in out and "4 GB earned" in out
