from datetime import datetime

from pydantic import BaseModel, Field


class ProjectOut(BaseModel):
    id: str
    name: str
    source_zip_filename: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    project_id: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    llm_config_id: str | None

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    project_id: str
    llm_config_id: str | None = None


class ReportSummary(BaseModel):
    total: int
    reachable: int
    uncertain: int
    not_reachable: int
    verifier_failed: int


class ReportOut(BaseModel):
    scan_id: str
    summary: ReportSummary
    html_url: str
    json_url: str


class LLMConfigIn(BaseModel):
    name: str = "default"
    provider_type: str = "openai_compatible"
    base_url: str | None = None
    api_key: str | None = None
    verify_model: str
    report_model: str | None = None
    # Capped rather than free-form: past 8 the wall-clock gain flattens while
    # the odds of the 429 that fails a whole scan keep climbing.
    concurrency: int = Field(default=1, ge=1, le=8)


class LLMConfigOut(BaseModel):
    id: str
    name: str
    provider_type: str
    base_url: str | None
    api_key_masked: str | None
    verify_model: str
    report_model: str | None
    is_active: bool
    concurrency: int

    model_config = {"from_attributes": True}


class LLMTestResult(BaseModel):
    success: bool
    error: str = ""
