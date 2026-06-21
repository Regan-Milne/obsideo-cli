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
