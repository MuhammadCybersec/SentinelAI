"""
===========================================================
Project : Sentinel AI
Module  : Finding Model
File ID : DB-MODEL-003
Version : 2.0.0
===========================================================

Description:
Stores discovered vulnerabilities and security findings.

===========================================================
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class Finding(Base):
    """
    Vulnerability Finding Model.
    """

    __tablename__ = "findings"

    # =====================================================
    # Primary Key
    # =====================================================

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # =====================================================
    # Project
    # =====================================================

    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id"),
        nullable=False,
        index=True,
    )

    # =====================================================
    # Basic Information
    # =====================================================

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="Info",
        index=True,
    )

    cvss: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="Open",
        index=True,
    )

    module: Mapped[str] = mapped_column(
        String(100),
        default="",
    )

    target: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    # =====================================================
    # Vulnerability Type
    # =====================================================

    vulnerability_type: Mapped[str] = mapped_column(
        String(100),
        default="",
        index=True,
    )

    # =====================================================
    # Scanner Information
    # =====================================================

    scanner_name: Mapped[str] = mapped_column(
        String(100),
        default="unknown",
        index=True,
    )

    scanner_version: Mapped[str] = mapped_column(
        String(50),
        default="1.0.0",
        nullable=True,
    )

    # =====================================================
    # Request Information
    # =====================================================

    url: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    method: Mapped[str] = mapped_column(
        String(10),
        default="GET",
    )

    parameter: Mapped[str] = mapped_column(
        String(255),
        default="",
    )

    payload: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    # =====================================================
    # Response Information
    # =====================================================

    status_code: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    response_time: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    # =====================================================
    # Evidence
    # =====================================================

    evidence: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    recommendation: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    reference: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    # =====================================================
    # Confidence & Verification
    # =====================================================

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    is_false_positive: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )

    verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )

    # =====================================================
    # Security Classification
    # =====================================================

    cwe: Mapped[str] = mapped_column(
        String(50),
        default="",
        index=True,
    )

    owasp: Mapped[str] = mapped_column(
        String(100),
        default="",
        index=True,
    )

    cve: Mapped[str] = mapped_column(
        String(50),
        default="",
        index=True,
    )

    # =====================================================
    # Tags & Metadata
    # =====================================================

    tags: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    metadata_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
    )

    # =====================================================
    # Dates
    # =====================================================

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    # =====================================================
    # String Representation
    # =====================================================

    def __repr__(self) -> str:
        return (
            f"<Finding("
            f"id='{self.id}', "
            f"title='{self.title}', "
            f"severity='{self.severity}', "
            f"status='{self.status}'"
            f")>"
        )

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss": self.cvss,
            "status": self.status,
            "module": self.module,
            "target": self.target,
            "vulnerability_type": self.vulnerability_type,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "confidence": self.confidence,
            "is_false_positive": self.is_false_positive,
            "verified": self.verified,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cve": self.cve,
            "tags": self.tags,
            "metadata_json": self.metadata_json,
            "discovered_at": (
                self.discovered_at.isoformat() if self.discovered_at else None
            ),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
