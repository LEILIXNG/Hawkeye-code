"""Unit tests for scanner/ingest.py's zip-slip and size-limit guards.

Uploaded zips are untrusted input (CLAUDE.md section 4) even though this
tool only ever runs on the operator's own machine.
"""
import zipfile

import pytest

from scanner.ingest import IngestError, common_root, safe_extract


def make_zip(tmp_path, entries: dict[str, bytes]):
    zip_path = tmp_path / "upload.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return zip_path


def infos_for(tmp_path, names):
    with zipfile.ZipFile(make_zip(tmp_path, {n: b"x" for n in names})) as zf:
        return zf.infolist()


class TestCommonRoot:
    def test_finds_the_single_wrapping_directory(self, tmp_path):
        assert common_root(infos_for(tmp_path, ["proj/src/A.java", "proj/README.md"])) == "proj/"

    def test_empty_when_entries_sit_at_the_top_level(self, tmp_path):
        assert common_root(infos_for(tmp_path, ["src/A.java", "README.md"])) == ""

    def test_empty_when_one_name_is_a_top_level_file(self, tmp_path):
        """`proj` and `proj.txt` are different roots -- stripping "proj/"
        here would drop the file entirely."""
        assert common_root(infos_for(tmp_path, ["proj/A.java", "other.txt"])) == ""

    def test_empty_for_a_root_holding_nothing_but_itself(self, tmp_path):
        assert common_root(infos_for(tmp_path, ["proj"])) == ""

    def test_never_strips_a_traversal_prefix(self, tmp_path):
        """Every entry under "../" is one root, but stripping it would turn
        a rejected zip-slip into a silently accepted ordinary file."""
        assert common_root(infos_for(tmp_path, ["../evil/a.txt", "../evil/b.txt"])) == ""


class TestSafeExtract:
    def test_strips_a_single_wrapping_directory(self, tmp_path):
        """GitHub's Download ZIP wraps everything in <repo>-<branch>/. Left
        in place it deepens every path by that much, which on Windows is the
        difference between a file being scanned and silently skipped."""
        zip_path = make_zip(tmp_path, {"VulnerableApp-master/src/A.java": b"class A {}"})
        dest = tmp_path / "workspace"
        safe_extract(zip_path, dest)
        assert (dest / "src" / "A.java").read_bytes() == b"class A {}"
        assert not (dest / "VulnerableApp-master").exists()

    def test_keeps_the_layout_when_there_is_no_single_root(self, tmp_path):
        zip_path = make_zip(tmp_path, {"src/A.java": b"a", "pom.xml": b"b"})
        dest = tmp_path / "workspace"
        safe_extract(zip_path, dest)
        assert (dest / "src" / "A.java").exists() and (dest / "pom.xml").exists()

    def test_rejects_an_archive_that_is_entirely_a_traversal(self, tmp_path):
        zip_path = make_zip(tmp_path, {"../evil/a.txt": b"pwned", "../evil/b.txt": b"pwned"})
        with pytest.raises(IngestError, match="escapes destination"):
            safe_extract(zip_path, tmp_path / "workspace")

    def test_still_rejects_traversal_inside_a_wrapped_archive(self, tmp_path):
        zip_path = make_zip(tmp_path, {"proj/ok.txt": b"a", "../evil.txt": b"pwned"})
        with pytest.raises(IngestError, match="escapes destination"):
            safe_extract(zip_path, tmp_path / "workspace")


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
