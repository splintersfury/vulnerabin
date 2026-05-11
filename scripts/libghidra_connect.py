"""Thin client for the LibGhidra Java extension's HTTP API host.

Foundation responsibilities only: healthz probe, version-pin parsing, and
lock primitives. The real LibGhidra Protobuf API calls (decompile, rename,
retype, etc.) land in the Pass 0 sub-plan and are loaded as GhidraSQL
skill files into the agent workspace at .claude/skills/ghidrasql/.
"""
from __future__ import annotations

import fcntl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping

_PLACEHOLDER = "TO_BE_SET_DURING_FIRST_INSTALL"


def healthz(url: str, timeout: float = 2.0) -> bool:
    """Return True iff `url` responds with HTTP 200 within `timeout` seconds.

    Returns False on empty URL, connection error, timeout, or non-2xx status.
    """
    if not url:
        return False
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, OSError):
        return False


def read_pin_file(path: Path) -> dict:
    """Parse a `key=value` pin file (e.g. vendor/libghidra.version).

    Ignores blank lines and `#`-prefixed comments. Returns a dict of the
    declared keys. Missing required keys are NOT an error here; use
    `is_placeholder_pin` to detect uninitialized pins.
    """
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def is_placeholder_pin(parsed: Mapping[str, str]) -> bool:
    """Return True if any tracked field still holds the placeholder string."""
    for k in ("commit", "sha256"):
        if parsed.get(k) == _PLACEHOLDER:
            return True
    return False


def acquire_exclusive_lock(lock_path: Path, *, blocking: bool = False) -> "object | None":
    """Acquire a exclusive flock on `lock_path`. Returns the file handle on
    success (caller must keep it open until they want to release), or None if
    the lock is held by another process and `blocking=False`.

    Creates the lock file if it does not exist. Parent directory must exist.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lf = open(lock_path, "w")
    flag = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
    try:
        fcntl.flock(lf, flag)
    except BlockingIOError:
        lf.close()
        return None
    return lf


def release_lock(lf) -> None:
    """Release a flock previously acquired via `acquire_exclusive_lock`."""
    try:
        fcntl.flock(lf, fcntl.LOCK_UN)
    finally:
        lf.close()
