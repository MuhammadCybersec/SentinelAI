"""
===========================================================
Project : Sentinel AI
Module  : Finding Model
File ID : DB-MODEL-003
Version : 1.0.0
===========================================================

Description:
Stores discovered vulnerabilities and security findings.

===========================================================
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)

from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

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
    # Request Information
    # =====================================================

    url: Mapped[str] = mapped_column(
        Text,
        default="",
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
