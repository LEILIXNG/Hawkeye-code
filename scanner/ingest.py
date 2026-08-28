"""A: extract an uploaded zip into an isolated workspace directory.

Uploaded zips are untrusted input even though everything runs on the same
machine — see docs/framework.md section 3.A and CLAUDE.md's "摄取到的代码
永远当作不可信数据" rule. This only ever reads/writes files; it never
executes anything from inside the archive.

Archives that wrap everything in a single top-level directory — what
GitHub's "Download ZIP" produces, e.g. VulnerableApp-master/ — get that
directory stripped. It carries no information the workspace does not
already have, it pushes every report path one level deeper than the same
project scanned from a checkout, and on Windows those wasted characters
are not free: see core.py's long_paths(), where files past MAX_PATH stop
being scanned at all, silently.
"""
import zipfile
from pathlib import Path

MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_FILE_COUNT = 20_000


class IngestError(Exception):
    pass


def common_root(infos: list[zipfile.ZipInfo]) -> str:
    """The single top-level directory every entry sits under, as a prefix
    ending in "/", or "" when the archive has more than one root.

    Returns "" for a single root holding nothing but itself, so an archive
    that is just an empty directory does not extract to an empty workspace
    that looks like a successful ingest.
    """
    roots = {name.split("/", 1)[0] for info in infos if (name := info.filename.lstrip("/"))}
    if len(roots) != 1:
        return ""
    root = roots.pop()
    # Never strip "." or "..": an archive whose entries all sit under "../"
    # is a traversal attempt, and stripping it would rewrite the attempt
    # into an ordinary file instead of letting safe_extract reject it.
    if root in ("", ".", ".."):
        return ""
    if not any(info.filename.lstrip("/").startswith(root + "/") for info in infos):
        return ""
    return root + "/"


def safe_extract(zip_path: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILE_COUNT:
            raise IngestError(f"zip contains {len(infos)} entries, exceeds limit of {MAX_FILE_COUNT}")

        strip = common_root(infos)
        total = 0
        targets = []
        for info in infos:
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise IngestError(
                    f"uncompressed size exceeds limit of {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
                )

            name = info.filename[len(strip):] if strip else info.filename
            if not name.strip("/"):
                continue

            target = (dest_dir / name).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise IngestError(f"zip entry escapes destination directory: {info.filename}")
            targets.append((info, target))

        for info, target in targets:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())

    return dest_dir
