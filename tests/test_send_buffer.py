"""Upload speed: the Windows send buffer."""

import socket

import pytest

from obsideo_core import config, storage


@pytest.fixture
def creds(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setenv("OBSIDEO_S3_ACCESS_KEY", "AKTEST")
    monkeypatch.setenv("OBSIDEO_S3_SECRET_KEY", "secret")
    monkeypatch.setenv("OBSIDEO_S3_BUCKET", "obsideo")
    storage.reset_client()
    yield tmp_path
    storage.reset_client()


def test_send_buffer_windows_only(monkeypatch):
    monkeypatch.delenv("OBSIDEO_SEND_BUFFER", raising=False)
    monkeypatch.setattr(storage.os, "name", "nt")
    assert storage._send_buffer() == 4 * 1024 * 1024
    monkeypatch.setattr(storage.os, "name", "posix")
    assert storage._send_buffer() == 0
    monkeypatch.setenv("OBSIDEO_SEND_BUFFER", "1048576")
    assert storage._send_buffer() == 1048576
    monkeypatch.setenv("OBSIDEO_SEND_BUFFER", "0")
    monkeypatch.setattr(storage.os, "name", "nt")
    assert storage._send_buffer() == 0


def test_client_connections_get_the_send_buffer(creds, monkeypatch):
    monkeypatch.setenv("OBSIDEO_SEND_BUFFER", "2097152")
    sess = storage._s3()._endpoint.http_session
    want = (socket.SOL_SOCKET, socket.SO_SNDBUF, 2097152)
    assert want in sess._socket_options
    assert want in sess._manager.connection_pool_kw["socket_options"]
    # botocore's own options (TCP_NODELAY) are kept
    assert any(o[1] == socket.TCP_NODELAY for o in sess._socket_options)


def test_widen_never_raises_on_unknown_client(monkeypatch):
    monkeypatch.setenv("OBSIDEO_SEND_BUFFER", "1024")
    storage._widen_send_buffer(object())
