"""SQLAlchemy models, matching docs/framework.md section 2's data model
(minus the User table — single-user local tool, no auth needed).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    source_zip_filename: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    status: Mapped[str] = mapped_column(String, default="queued")
    # queued|ingesting|scanning|verifying|reporting|done|failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    project: Mapped["Project"] = relationship(back_populates="scans")
    candidates: Mapped[list["Candidate"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    report: Mapped["Report"] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")


class Candidate(Base):
    __tablename__ = "candidates"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe: Mapped[str | None] = mapped_column(JSON, nullable=True)
    owasp: Mapped[str | None] = mapped_column(JSON, nullable=True)
    source_file: Mapped[str] = mapped_column(String)
    source_line: Mapped[int] = mapped_column(Integer)
    sink_file: Mapped[str] = mapped_column(String)
    sink_line: Mapped[int] = mapped_column(Integer)
    dedup_key: Mapped[str] = mapped_column(String)
    is_intraprocedural: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="candidates")
    finding: Mapped["Finding"] = relationship(back_populates="candidate", uselist=False, cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"))
    reachable: Mapped[str] = mapped_column(String)  # yes|no|uncertain
    sanitized: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploit_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    verifier_model: Mapped[str | None] = mapped_column(String, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    candidate: Mapped["Candidate"] = relationship(back_populates="finding")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), unique=True)
    html_path: Mapped[str] = mapped_column(String)
    json_path: Mapped[str] = mapped_column(String)
    summary: Mapped[dict] = mapped_column(JSON)

    scan: Mapped["Scan"] = relationship(back_populates="report")


class LLMConfig(Base):
    __tablename__ = "llm_configs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    provider_type: Mapped[str] = mapped_column(String)  # "openai_compatible" for Phase 1
    base_url: Mapped[str | None] = mapped_column(String, nullable=True)
    api_key: Mapped[str | None] = mapped_column(String, nullable=True)
    verify_model: Mapped[str] = mapped_column(String)
    report_model: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
