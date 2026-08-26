"""Unit tests for scanner/ingest.py's zip-slip and size-limit guards.

Uploaded zips are untrusted input (CLAUDE.md section 4) even though this
tool only ever runs on the operator's own machine.
"""
import zipfile

import pytest

from scanner.ingest import IngestError, safe_extract


def make_zip(tmp_path, entries: dict[str, bytes]):
    zip_path = tmp_path / "upload.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return zip_path


class TestSafeExtract:
    def test_extracts_normal_files(self, tmp_path):
        zip_path = make_zip(tmp_path, {"src/A.java": b"class A {}", "README.md": b"hi"})
        dest = tmp_path / "workspace"
        safe_extract(zip_path, dest)
        assert (dest / "src" / "A.java").read_bytes() == b"class A {}"
        assert (dest / "README.md").read_bytes() == b"hi"

    def test_rejects_path_traversal_entry(self, tmp_path):
        zip_path = make_zip(tmp_path, {"../../evil.txt": b"pwned"})
        dest = tmp_path / "workspace"
        with pytest.raises(IngestError, match="escapes destination"):
            safe_extract(zip_path, dest)

    def test_rejects_absolute_path_entry(self, tmp_path):
        # zipfile normalizes leading slashes away on read, but a crafted
        # entry can still resolve outside dest via ".." segments deeper in
        # the path -- this covers that shape too.
        zip_path = make_zip(tmp_path, {"a/../../escape.txt": b"pwned"})
        dest = tmp_path / "sub" / "workspace"
        with pytest.raises(IngestError, match="escapes destination"):
            safe_extract(zip_path, dest)

    def test_rejects_too_many_entries(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.ingest.MAX_FILE_COUNT", 2)
        zip_path = make_zip(tmp_path, {"a.txt": b"1", "b.txt": b"2", "c.txt": b"3"})
        dest = tmp_path / "workspace"
        with pytest.raises(IngestError, match="entries"):
            safe_extract(zip_path, dest)

    def test_rejects_zip_bomb_by_uncompressed_size(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.ingest.MAX_TOTAL_UNCOMPRESSED_BYTES", 10)
        zip_path = make_zip(tmp_path, {"big.txt": b"x" * 100})
        dest = tmp_path / "workspace"
        with pytest.raises(IngestError, match="uncompressed size"):
            safe_extract(zip_path, dest)
