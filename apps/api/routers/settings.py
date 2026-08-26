from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from apps.api import models, schemas
from apps.api.database import get_db
from llm_gateway.providers.openai_compatible import OpenAICompatibleProvider

router = APIRouter(prefix="/settings/llm", tags=["settings"])


def _mask(key: str | None) -> str | None:
    if not key:
        return None
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"


def _to_out(row: models.LLMConfig) -> schemas.LLMConfigOut:
    return schemas.LLMConfigOut(
        id=row.id,
        name=row.name,
        provider_type=row.provider_type,
        base_url=row.base_url,
        api_key_masked=_mask(row.api_key),
        verify_model=row.verify_model,
        report_model=row.report_model,
        is_active=row.is_active,
    )


@router.get("", response_model=schemas.LLMConfigOut | None)
def get_active_config(db: Session = Depends(get_db)):
    row = db.query(models.LLMConfig).filter_by(is_active=True).first()
    return _to_out(row) if row else None


@router.post("", response_model=schemas.LLMConfigOut)
def save_config(payload: schemas.LLMConfigIn, db: Session = Depends(get_db)):
    # Single-user tool: only one config is ever "active" at a time.
    db.query(models.LLMConfig).update({"is_active": False})

    row = models.LLMConfig(
        name=payload.name,
        provider_type=payload.provider_type,
        base_url=payload.base_url,
        api_key=payload.api_key,
        verify_model=payload.verify_model,
        report_model=payload.report_model,
        is_active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_out(row)


@router.post("/test", response_model=schemas.LLMTestResult)
def test_config(payload: schemas.LLMConfigIn):
    if not payload.api_key:
        return schemas.LLMTestResult(success=False, error="api_key is required to test a connection")
    provider = OpenAICompatibleProvider(base_url=payload.base_url, api_key=payload.api_key)
    success, error = provider.test_connection(model=payload.verify_model)
    return schemas.LLMTestResult(success=success, error=error)
