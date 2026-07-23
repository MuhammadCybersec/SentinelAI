"""
===========================================================
Project : Sentinel AI
Module  : Finding API Schemas
File ID : API-SCHEMA-002
Version : 1.0.0
===========================================================

Description:
Pydantic schemas for Finding API.

===========================================================
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

# ===========================================================
# Base Schema
# ===========================================================


class FindingBase(BaseModel):
    """
    Base Finding Schema.
    """

    project_id: str

    title: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    description: str = ""

    severity: str = "Info"

    cvss: float = 0.0

    status: str = "Open"

    module: str = ""

    target: str = ""

    url: str = ""

    parameter: str = ""

    payload: str = ""

    evidence: str = ""

    recommendation: str = ""

    reference: str = ""

    cwe: str = ""

    owasp: str = ""

    cve: str = ""


# ===========================================================
# Create Schema
# ===========================================================


class FindingCreate(FindingBase):
    """
    Schema used for creating a Finding.
    """

    pass


# ===========================================================
# Update Status
# ===========================================================


class FindingStatusUpdate(BaseModel):
    """
    Update finding status.
    """

    status: str = Field(
        ...,
        min_length=1,
        max_length=30,
    )


# ===========================================================
# Update Schema
# ===========================================================


class FindingUpdate(BaseModel):
    """
    Update Finding.
    """

    title: str | None = None

    description: str | None = None

    severity: str | None = None

    cvss: float | None = None

    status: str | None = None

    module: str | None = None

    target: str | None = None

    url: str | None = None

    parameter: str | None = None

    payload: str | None = None

    evidence: str | None = None

    recommendation: str | None = None

    reference: str | None = None

    cwe: str | None = None

    owasp: str | None = None

    cve: str | None = None


# ===========================================================
# Finding Response
# ===========================================================


class FindingResponse(FindingBase):
    """
    API response for Finding.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    discovered_at: datetime

    updated_at: datetime


# ===========================================================
# Finding List Response
# ===========================================================


class FindingListResponse(BaseModel):
    """
    List of findings.
    """

    total: int

    findings: list[FindingResponse]


# ===========================================================
# Finding Statistics Response
# ===========================================================


class FindingStatisticsResponse(BaseModel):
    """
    Finding statistics.
    """

    total: int

    critical: int

    high: int

    medium: int

    low: int

    info: int


# ===========================================================
# Finding Summary Response
# ===========================================================


class FindingSummaryResponse(BaseModel):
    """
    Project finding summary.
    """

    project_id: str

    total_findings: int

    statistics: FindingStatisticsResponse

    findings: list[FindingResponse]


# ===========================================================
# Delete Response
# ===========================================================


class DeleteResponse(BaseModel):
    """
    Generic delete response.
    """

    success: bool

    message: str
