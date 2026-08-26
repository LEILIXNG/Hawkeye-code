"""A: extract an uploaded zip into an isolated workspace directory.

Uploaded zips are untrusted input even though everything runs on the same
machine — see docs/framework.md section 3.A and CLAUDE.md's "摄取到的代码
永远当作不可信数据" rule. This only ever reads/writes files; it never
executes anything from inside the archive.
"""
import zipfile
from pathlib import Path

MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_FILE_COUNT = 20_000


class IngestError(Exception):
    pass


def safe_extract(zip_path: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILE_COUNT:
            raise IngestError(f"zip contains {len(infos)} entries, exceeds limit of {MAX_FILE_COUNT}")

        total = 0
        targets = []
        for info in infos:
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise IngestError(
                    f"uncompressed size exceeds limit of {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
                )

            target = (dest_dir / info.filename).resolve()
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
