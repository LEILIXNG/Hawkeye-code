from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from apps.api import models, schemas
from apps.api.database import get_db
from scanner.common import UPLOADS_DIR, ensure_data_dir

router = APIRouter(prefix="/uploads", tags=["uploads"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("", response_model=schemas.ProjectOut)
async def upload_zip(file: UploadFile, db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "only .zip uploads are supported")

    ensure_data_dir()
    project = models.Project(name=file.filename[:-4], source_zip_filename=file.filename)
    db.add(project)
    db.flush()

    dest = UPLOADS_DIR / f"{project.id}.zip"
    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                db.rollback()
                raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES} byte limit")
            out.write(chunk)

    db.commit()
    db.refresh(project)
    return project
