"""Create and verify a deterministic ZIP of explicitly selected review files.

Archive members use portable relative POSIX names. Sources remain untouched;
symlinks, special files and ambiguous member names are rejected before writing.
The returned hashes describe exact source bytes and the completed archive.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Any
import unicodedata
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile, ZipInfo


class ReviewPackageError(ValueError):
    """A source, archive member or verification expectation is unsafe or invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewPackageError(message)


def _member_key(name: object) -> str:
    """Validate a portable relative name and return its collision key."""
    _require(isinstance(name, str) and bool(name), "ZIP member name must be nonempty text")
    name = str(name)
    _require("\\" not in name and ":" not in name, f"Unsafe ZIP member name {name!r}")
    _require(not PurePosixPath(name).is_absolute() and not PureWindowsPath(name).drive,
             f"Absolute or drive-qualified ZIP member name {name!r}")
    _require(not any(ord(character) < 32 or ord(character) == 127 for character in name),
             f"Control character in ZIP member name {name!r}")
    components = name.split("/")
    _require(all(component and component not in (".", "..") for component in components),
             f"Dot or empty ZIP path component in {name!r}")
    _require(all(component == component.rstrip(" .") for component in components),
             f"Nonportable trailing dot or space in ZIP member name {name!r}")
    return unicodedata.normalize("NFC", name).casefold()


def _validated_names(names: object) -> list[str]:
    _require(isinstance(names, (list, tuple)), "ZIP member names must be a list")
    seen: set[str] = set()
    result = []
    for name in names:
        key = _member_key(name)
        _require(key not in seen, f"Duplicate normalized ZIP member name {name!r}")
        seen.add(key)
        result.append(name)
    _require(bool(result), "Review ZIP must contain at least one regular file")
    return result


def _reject_symlink_chain(path: Path) -> None:
    """Reject symlink/reparse components, including a linked parent directory."""
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        _require(not stat.S_ISLNK(info.st_mode), f"Symlink path is forbidden: {component}")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        _require(not getattr(info, "st_file_attributes", 0) & reparse_flag,
                 f"Reparse path is forbidden: {component}")


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_review_zip(path: Path, expected_hashes: Mapping[str, str]) -> None:
    """Verify exact member names, file types, CRCs and expected payload hashes.

    Every member must be expected exactly once. No archive is extracted, and
    unsafe names are rejected even when they appear in the expected mapping.
    """
    archive_path = Path(path)
    try:
        _require(isinstance(expected_hashes, Mapping), "expected_hashes must be an object")
        expected_names = _validated_names(list(expected_hashes))
        for name, digest in expected_hashes.items():
            _require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                     f"Invalid expected SHA-256 for {name!r}")
        _reject_symlink_chain(archive_path)
        _require(stat.S_ISREG(archive_path.stat().st_mode), f"Archive is not a regular file: {archive_path}")
        with ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            actual_names = _validated_names([info.filename for info in infos])
            _require(set(actual_names) == set(expected_names), "ZIP member names differ from expected inventory")
            for info in infos:
                _require(info.orig_filename == info.filename,
                         f"ZIP member contains a truncated or ambiguous name: {info.orig_filename!r}")
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                _require(not info.is_dir() and not info.external_attr & 0x10
                         and kind in (0, stat.S_IFREG),
                         f"ZIP member is not a regular file: {info.filename!r}")
                digest = sha256()
                with archive.open(info, "r") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                _require(digest.hexdigest() == expected_hashes[info.filename],
                         f"ZIP payload SHA-256 mismatch: {info.filename!r}")
            _require(archive.testzip() is None, "ZIP CRC verification failed")
    except ReviewPackageError:
        raise
    except (OSError, BadZipFile, RuntimeError, NotImplementedError, ValueError) as exc:
        raise ReviewPackageError(f"Cannot verify review ZIP {archive_path}: {exc}") from exc


def create_review_zip(output_path: Path, files: Mapping[str, Path]) -> dict[str, Any]:
    """Write each source once in sorted order, then verify the complete package.

    The output parent directory must already exist. File timestamps, permissions
    and member ordering are fixed, so unchanged inputs yield identical bytes.
    Sources and an existing output must be regular files without linked parents.
    """
    archive_path = Path(output_path)
    try:
        _require(isinstance(files, Mapping), "files must map ZIP names to source paths")
        names = sorted(_validated_names(list(files)))
        _reject_symlink_chain(archive_path)
        _require(archive_path.parent.is_dir(), f"Archive parent directory is missing: {archive_path.parent}")
        if archive_path.exists():
            _require(stat.S_ISREG(archive_path.stat().st_mode), f"Archive target is not a regular file: {archive_path}")
        sources: dict[str, Path] = {}
        inventory = []
        for name in names:
            source = Path(files[name])
            _reject_symlink_chain(source)
            _require(stat.S_ISREG(source.stat().st_mode), f"Source is not a regular file: {source}")
            same_path = source.resolve() == archive_path.resolve()
            if archive_path.exists():
                same_path = same_path or source.samefile(archive_path)
            _require(not same_path, f"Source and archive refer to the same file: {source}")
            sources[name] = source
            inventory.append({"filename": name, "sha256": _hash_file(source), "size": source.stat().st_size})
        with ZipFile(archive_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for entry in inventory:
                name = entry["filename"]
                payload = sources[name].read_bytes()
                _require(sha256(payload).hexdigest() == entry["sha256"] and len(payload) == entry["size"],
                         f"Source changed while packaging: {sources[name]}")
                info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, payload, compress_type=ZIP_DEFLATED, compresslevel=9)
        expected = {entry["filename"]: entry["sha256"] for entry in inventory}
        verify_review_zip(archive_path, expected)
        for entry in inventory:
            _require(_hash_file(sources[entry["filename"]]) == entry["sha256"],
                     f"Source changed during package verification: {sources[entry['filename']]}")
        return {"entries": inventory, "archive_sha256": _hash_file(archive_path), "testzip_passed": True}
    except ReviewPackageError:
        raise
    except (OSError, BadZipFile, RuntimeError, NotImplementedError, ValueError) as exc:
        raise ReviewPackageError(f"Cannot create review ZIP {archive_path}: {exc}") from exc


__all__ = ("ReviewPackageError", "create_review_zip", "verify_review_zip")
