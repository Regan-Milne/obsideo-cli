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
