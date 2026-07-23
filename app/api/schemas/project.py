"""
===========================================================
Project : Sentinel AI
Module  : Project API Schemas
File ID : API-SCHEMA-001
Version : 1.0.0
===========================================================

Description:
Pydantic schemas for Project API.

===========================================================
"""

from __future__ import annotations

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

# ===========================================================
# Create Project
# ===========================================================


class ProjectCreate(BaseModel):
    """
    Request schema for creating a project.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="Project name",
    )

    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Target URL",
    )

    description: str = Field(
        default="",
        max_length=500,
        description="Project description",
    )


# ===========================================================
# Update Project
# ===========================================================


class ProjectUpdate(BaseModel):
    """
    Request schema for updating a project.
    """

    name: str | None = Field(
        default=None,
        max_length=150,
    )

    target: str | None = Field(
        default=None,
        max_length=500,
    )

    description: str | None = Field(
        default=None,
        max_length=500,
    )

    status: str | None = Field(
        default=None,
        max_length=50,
    )
    # ===========================================================


# Project Response
# ===========================================================


class ProjectResponse(BaseModel):
    """
    Response schema for a project.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    name: str

    target: str

    description: str | None

    status: str


# ===========================================================
# Project Summary
# ===========================================================


class ProjectSummary(BaseModel):
    """
    Lightweight project summary.
    """

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: str

    name: str

    status: str


# ===========================================================
# Project List Response
# ===========================================================


class ProjectListResponse(BaseModel):
    """
    Response schema for project list.
    """

    total: int

    projects: list[ProjectSummary]


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    sample = ProjectCreate(
        name="OWASP Juice Shop",
        target="https://demo.owasp-juice.shop",
        description="Demo Project",
    )

    print("=" * 60)
    print("Project Schema Test")
    print("=" * 60)

    print()

    print(sample.model_dump())
