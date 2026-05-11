"""Tests for libghidra_connect: healthz, version pin, lock primitives."""
from __future__ import annotations

import http.server
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import libghidra_connect  # type: ignore


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/libghidra/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_a, **_kw):  # silence
        pass


@pytest.fixture()
def healthz_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _OkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/libghidra/healthz"
    server.shutdown()
    thread.join(timeout=2)


def test_healthz_true_when_endpoint_responds_200(healthz_server):
    assert libghidra_connect.healthz(healthz_server, timeout=1.0) is True


def test_healthz_false_when_endpoint_unreachable():
    assert libghidra_connect.healthz(
        "http://127.0.0.1:1/nonexistent", timeout=0.5
    ) is False


def test_healthz_false_when_url_is_empty():
    assert libghidra_connect.healthz("", timeout=0.5) is False


def test_check_version_pin_reads_pin_file(tmp_path):
    pin = tmp_path / "libghidra.version"
    pin.write_text("url=https://example/repo\ncommit=abc123\nsha256=deadbeef\n")
    parsed = libghidra_connect.read_pin_file(pin)
    assert parsed == {
        "url": "https://example/repo",
        "commit": "abc123",
        "sha256": "deadbeef",
    }


def test_check_version_pin_rejects_placeholder_values(tmp_path):
    pin = tmp_path / "libghidra.version"
    pin.write_text(
        "url=https://example/repo\n"
        "commit=TO_BE_SET_DURING_FIRST_INSTALL\n"
        "sha256=TO_BE_SET_DURING_FIRST_INSTALL\n"
    )
    parsed = libghidra_connect.read_pin_file(pin)
    assert libghidra_connect.is_placeholder_pin(parsed) is True


def test_acquire_exclusive_lock_returns_handle_when_free(tmp_path):
    lock = tmp_path / "test.lock"
    lf = libghidra_connect.acquire_exclusive_lock(lock)
    try:
        assert lf is not None
        assert lock.is_file()
    finally:
        libghidra_connect.release_lock(lf)


def test_acquire_exclusive_lock_returns_none_when_held(tmp_path):
    lock = tmp_path / "test.lock"
    first = libghidra_connect.acquire_exclusive_lock(lock)
    try:
        # Second non-blocking attempt must return None.
        second = libghidra_connect.acquire_exclusive_lock(lock, blocking=False)
        assert second is None
    finally:
        libghidra_connect.release_lock(first)


def test_lock_can_be_reacquired_after_release(tmp_path):
    lock = tmp_path / "test.lock"
    first = libghidra_connect.acquire_exclusive_lock(lock)
    assert first is not None
    libghidra_connect.release_lock(first)
    second = libghidra_connect.acquire_exclusive_lock(lock)
    assert second is not None
    libghidra_connect.release_lock(second)
