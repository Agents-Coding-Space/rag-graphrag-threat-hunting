"""Every atomic writer must survive a transient Windows file lock.

The review found that a targeted fix in two modules left the same class of bug in
scripts/build_vector_index.py, so a full-suite run still failed intermittently. This test pins
the shared helper and asserts that no writer bypasses it.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting import atomic_fs  # noqa: E402


def test_replace_succeeds_first_time(tmp_path):
    src, dst = tmp_path / "a.tmp", tmp_path / "a.json"
    src.write_text("x", encoding="utf-8")
    atomic_fs.replace_with_retry(src, dst)
    assert dst.read_text(encoding="utf-8") == "x"
    assert not src.exists()


def test_replace_retries_transient_lock(tmp_path, monkeypatch):
    src, dst = tmp_path / "b.tmp", tmp_path / "b.json"
    src.write_text("y", encoding="utf-8")
    real, calls = os.replace, {"n": 0}

    def flaky(a, b):
        calls["n"] += 1
        if calls["n"] < 3:
            exc = PermissionError(errno.EACCES, "locked")
            exc.winerror = 5
            raise exc
        return real(a, b)

    monkeypatch.setattr(atomic_fs.os, "replace", flaky)
    atomic_fs.replace_with_retry(src, dst, delay=0)
    assert dst.read_text(encoding="utf-8") == "y"
    assert calls["n"] == 3


def test_real_permission_error_is_not_masked(tmp_path, monkeypatch):
    """A genuine permission failure must surface promptly, not be retried forever."""
    src, dst = tmp_path / "c.tmp", tmp_path / "c.json"
    src.write_text("z", encoding="utf-8")
    calls = {"n": 0}

    def bad(a, b):
        calls["n"] += 1
        exc = PermissionError(errno.EPERM, "denied")
        exc.winerror = 5
        raise exc

    monkeypatch.setattr(atomic_fs.os, "replace", bad)
    with pytest.raises(PermissionError):
        atomic_fs.replace_with_retry(src, dst, attempts=3, delay=0)
    assert calls["n"] == 3


def test_non_lock_error_propagates_without_retry(tmp_path, monkeypatch):
    src, dst = tmp_path / "d.tmp", tmp_path / "d.json"
    src.write_text("w", encoding="utf-8")
    calls = {"n": 0}

    def missing(a, b):
        calls["n"] += 1
        raise FileNotFoundError(errno.ENOENT, "gone")

    monkeypatch.setattr(atomic_fs.os, "replace", missing)
    with pytest.raises(FileNotFoundError):
        atomic_fs.replace_with_retry(src, dst, delay=0)
    assert calls["n"] == 1


def test_bound_is_respected(tmp_path, monkeypatch):
    src, dst = tmp_path / "e.tmp", tmp_path / "e.json"
    src.write_text("v", encoding="utf-8")
    calls = {"n": 0}

    def always(a, b):
        calls["n"] += 1
        exc = PermissionError(errno.EACCES, "locked")
        exc.winerror = 5
        raise exc

    monkeypatch.setattr(atomic_fs.os, "replace", always)
    with pytest.raises(PermissionError):
        atomic_fs.replace_with_retry(src, dst, attempts=4, delay=0)
    assert calls["n"] == 4


def test_no_source_file_bypasses_the_helper():
    """A new os.replace in src/ or scripts/ would silently reintroduce the class of bug."""
    offenders = []
    for base in ("src", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            if path.name == "atomic_fs.py":
                continue
            if "os.replace(" in path.read_text(encoding="utf-8", errors="replace"):
                offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == [], f"use replace_with_retry instead of os.replace in {offenders}"
