"""
===========================================================
Project : Sentinel AI
Module  : Recon Result Database Model
File ID : DB-MODEL-003
Version : 1.0.0
===========================================================

Description:
Stores every reconnaissance finding.

===========================================================
"""

from __future__ import annotations

from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text

from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.models.base_model import BaseModel


class ReconResult(BaseModel):
    """
    Stores every recon finding.
    """

    __tablename__ = "recon_results"

    # ==========================================
    # Project ID
    # ==========================================

    project_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
    )

    # ==========================================
    # Recon Module
    # Example:
    # crawler
    # wayback
    # javascript
    # waf
    # api
    # ==========================================

    module: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    # ==========================================
    # Target
    # ==========================================

    target: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    # ==========================================
    # URL
    # ==========================================

    url: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )

    # ==========================================
    # Source
    # crawler
    # wayback
    # js
    # api
    # ==========================================

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    # ==========================================
    # HTTP Status
    # ==========================================

    status_code: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    # ==========================================
    # Risk
    # Low
    # Medium
    # High
    # Critical
    # ==========================================

    risk: Mapped[str] = mapped_column(
        String(20),
        default="Unknown",
    )

    # ==========================================
    # Extra Data
    # JSON string
    # ==========================================

    data: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
