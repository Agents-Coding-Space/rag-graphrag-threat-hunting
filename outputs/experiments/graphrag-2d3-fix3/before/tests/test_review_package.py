"""Real archive round trips and deliberately unsafe ZIP inputs."""

from hashlib import sha256
from pathlib import Path
import stat
import warnings
from zipfile import ZIP_STORED, ZipFile, ZipInfo

import pytest

from threat_hunting.evaluation.review_package import (
    ReviewPackageError, create_review_zip, verify_review_zip,
)


def source(tmp_path, name="source.txt", payload=b"review payload\n"):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def digest(payload=b"review payload\n"):
    return sha256(payload).hexdigest()


def write_raw_archive(path, entries):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with ZipFile(path, "w") as archive:
            for name, payload in entries:
                archive.writestr(name, payload)


def test_roundtrip_inventory_exact_source_bytes_unique_entries_and_crc(tmp_path):
    first = source(tmp_path, "first.json", b'{"approval":"Nguyen Hong Phong"}\n')
    second = source(tmp_path, "second.txt", "Báo cáo kiểm tra\n".encode("utf-8"))
    paths = {"reports/second.txt": second, "artifacts/first.json": first}
    before = {path: path.read_bytes() for path in paths.values()}
    output = tmp_path / "review.zip"
    result = create_review_zip(output, paths)
    assert result == {
        "entries": [{"filename": name, "sha256": sha256(paths[name].read_bytes()).hexdigest(),
                     "size": len(paths[name].read_bytes())} for name in sorted(paths)],
        "archive_sha256": sha256(output.read_bytes()).hexdigest(), "testzip_passed": True,
    }
    expected = {item["filename"]: item["sha256"] for item in result["entries"]}
    assert verify_review_zip(output, expected) is None
    assert {path: path.read_bytes() for path in paths.values()} == before
    with ZipFile(output) as archive:
        assert archive.namelist() == sorted(paths)
        assert len(set(archive.namelist())) == len(paths)
        assert archive.testzip() is None
        for name in paths:
            assert archive.read(name) == before[paths[name]]
            assert archive.getinfo(name).date_time == (1980, 1, 1, 0, 0, 0)
            assert stat.S_ISREG(archive.getinfo(name).external_attr >> 16)


def test_identical_payloads_and_reversed_mapping_produce_identical_archive_bytes(tmp_path):
    a, b = source(tmp_path, "a.txt", b"a"), source(tmp_path, "b.txt", b"b")
    first, second = tmp_path / "first.zip", tmp_path / "second.zip"
    result_a = create_review_zip(first, {"a.txt": a, "b.txt": b})
    result_b = create_review_zip(second, {"b.txt": b, "a.txt": a})
    assert first.read_bytes() == second.read_bytes()
    assert result_a == result_b


@pytest.mark.parametrize("name", [
    "../escape.txt", "a/../escape.txt", "./file.txt", "a/./file.txt", "/absolute.txt",
    "C:/absolute.txt", "C:relative.txt", "folder/C:stream.txt", "\\\\host\\share\\file.txt",
    "folder\\file.txt", "a//file.txt", "trailing/", "", "file.txt\0hidden", "line\nname",
    "folder./file.txt", "folder /file.txt", "file.txt ",
])
def test_unsafe_creation_names_are_rejected_before_archive_is_written(tmp_path, name):
    payload = source(tmp_path)
    output = tmp_path / "review.zip"
    with pytest.raises(ReviewPackageError):
        create_review_zip(output, {name: payload})
    assert not output.exists()


@pytest.mark.parametrize("names", [("File.txt", "file.txt"), ("café.txt", "cafe\u0301.txt")])
def test_normalized_creation_name_collisions_are_rejected(tmp_path, names):
    payload = source(tmp_path)
    with pytest.raises(ReviewPackageError, match="Duplicate normalized"):
        create_review_zip(tmp_path / "review.zip", {names[0]: payload, names[1]: payload})


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "C:/drive.txt",
                                 "folder\\file.txt", "folder/./file.txt", "folder//file.txt"])
def test_verifier_rejects_unsafe_names_inside_real_zip(tmp_path, name):
    output = tmp_path / "review.zip"
    write_raw_archive(output, [(name, b"review payload\n")])
    with pytest.raises(ReviewPackageError):
        verify_review_zip(output, {"safe.txt": digest()})


@pytest.mark.parametrize("names", [("same.txt", "same.txt"), ("File.txt", "file.txt"),
                                   ("café.txt", "cafe\u0301.txt")])
def test_verifier_rejects_actual_duplicate_and_normalized_duplicate_members(tmp_path, names):
    output = tmp_path / "review.zip"
    write_raw_archive(output, [(name, b"review payload\n") for name in names])
    with pytest.raises(ReviewPackageError, match="Duplicate normalized"):
        verify_review_zip(output, {"same.txt": digest()})


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644,
                                  stat.S_IFCHR | 0o600, stat.S_IFDIR | 0o755])
def test_zip_symlink_and_special_file_flags_are_rejected(tmp_path, mode):
    output = tmp_path / "review.zip"
    info = ZipInfo("payload.txt")
    info.create_system = 3
    info.external_attr = mode << 16
    with ZipFile(output, "w") as archive:
        archive.writestr(info, b"review payload\n")
    with pytest.raises(ReviewPackageError, match="not a regular file"):
        verify_review_zip(output, {"payload.txt": digest()})


def test_actual_directory_zip_entry_is_rejected(tmp_path):
    output = tmp_path / "review.zip"
    write_raw_archive(output, [("directory/", b"")])
    with pytest.raises(ReviewPackageError):
        verify_review_zip(output, {"directory/file.txt": digest(b"")})


@pytest.mark.parametrize("expectation", ["wrong_hash", "missing_entry", "unexpected_entry", "invalid_hash"])
def test_exact_member_set_and_payload_hashes_are_enforced(tmp_path, expectation):
    output = tmp_path / "review.zip"
    write_raw_archive(output, [("payload.txt", b"review payload\n")])
    expected = {"payload.txt": digest()}
    if expectation == "wrong_hash":
        expected["payload.txt"] = "0" * 64
    elif expectation == "missing_entry":
        expected["other.txt"] = digest()
    elif expectation == "unexpected_entry":
        expected = {"other.txt": digest()}
    else:
        expected["payload.txt"] = "not-a-sha256"
    with pytest.raises(ReviewPackageError):
        verify_review_zip(output, expected)


def test_corrupted_payload_crc_is_rejected(tmp_path):
    output = tmp_path / "review.zip"
    info = ZipInfo("payload.txt")
    info.compress_type = ZIP_STORED
    with ZipFile(output, "w") as archive:
        archive.writestr(info, b"original-payload")
    content = output.read_bytes()
    assert content.count(b"original-payload") == 1
    output.write_bytes(content.replace(b"original-payload", b"modified-payload"))
    with pytest.raises(ReviewPackageError):
        verify_review_zip(output, {"payload.txt": digest(b"original-payload")})


def test_source_cannot_be_archive_and_original_bytes_are_preserved(tmp_path):
    payload = source(tmp_path, "existing.zip")
    before = payload.read_bytes()
    with pytest.raises(ReviewPackageError, match="same file"):
        create_review_zip(payload, {"payload.txt": payload})
    assert payload.read_bytes() == before


def test_source_hardlink_to_archive_is_rejected_without_truncation(tmp_path):
    payload = source(tmp_path)
    output = tmp_path / "review.zip"
    output.hardlink_to(payload)
    with pytest.raises(ReviewPackageError, match="same file"):
        create_review_zip(output, {"payload.txt": payload})
    assert payload.read_bytes() == b"review payload\n"


def test_directory_source_is_refused_before_archive_write(tmp_path):
    output = tmp_path / "review.zip"
    with pytest.raises(ReviewPackageError, match="not a regular file"):
        create_review_zip(output, {"payload.txt": tmp_path})
    assert not output.exists()


def test_missing_source_is_reported_with_filename(tmp_path):
    output = tmp_path / "review.zip"
    with pytest.raises(ReviewPackageError, match="missing.txt"):
        create_review_zip(output, {"payload.txt": tmp_path / "missing.txt"})
    assert not output.exists()


def test_empty_package_and_nonzip_file_are_refused(tmp_path):
    with pytest.raises(ReviewPackageError, match="at least one"):
        create_review_zip(tmp_path / "review.zip", {})
    path = source(tmp_path, "not.zip", b"not a ZIP")
    with pytest.raises(ReviewPackageError):
        verify_review_zip(path, {"payload.txt": digest()})


@pytest.mark.parametrize("location", ["source", "source_parent", "archive"])
def test_linked_paths_are_rejected_even_with_regular_payload(tmp_path, monkeypatch, location):
    """Simulate lstat on Windows without requiring symlink-creation privilege."""
    payload = source(tmp_path)
    output = tmp_path / "review.zip"
    link_path = payload if location == "source" else payload.parent if location == "source_parent" else output
    original = Path.lstat
    def linked_lstat(path, *args, **kwargs):
        if path == link_path:
            class LinkStat:
                st_mode = stat.S_IFLNK | 0o777
                st_file_attributes = 0
            return LinkStat()
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", linked_lstat)
    with pytest.raises(ReviewPackageError, match="Symlink"):
        create_review_zip(output, {"payload.txt": payload})
    assert not output.exists()


def test_windows_reparse_source_is_refused(tmp_path, monkeypatch):
    payload = source(tmp_path)
    original = Path.lstat
    def reparse_lstat(path, *args, **kwargs):
        if path == payload:
            class ReparseStat:
                st_mode = stat.S_IFREG | 0o644
                st_file_attributes = 0x400
            return ReparseStat()
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    with pytest.raises(ReviewPackageError, match="Reparse"):
        create_review_zip(tmp_path / "review.zip", {"payload.txt": payload})


def test_source_changed_between_hashing_and_zip_write_is_detected(tmp_path, monkeypatch):
    payload = source(tmp_path)
    original = Path.read_bytes
    def changing_read(path):
        if path == payload:
            return b"changed payload\n"
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", changing_read)
    with pytest.raises(ReviewPackageError, match="Source changed"):
        create_review_zip(tmp_path / "review.zip", {"payload.txt": payload})
