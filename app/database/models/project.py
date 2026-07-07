"""
===========================================================
Project : Sentinel AI
Module  : Project Database Model
File ID : DB-MODEL-002
Version : 0.0.1
===========================================================

Description:
Defines the Project ORM model.

===========================================================
"""

# ===========================================================
# DB-MODEL-002
# Imports
# ===========================================================

from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.models.base_model import BaseModel


# ===========================================================
# DB-MODEL-003
# Project Model
# ===========================================================

class Project(BaseModel):
    """
    Represents a security assessment project.
    """

    # -------------------------------------------------------
    # Database Table Name
    # -------------------------------------------------------

    __tablename__ = "projects"

    # -------------------------------------------------------
    # Project Name
    # -------------------------------------------------------

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    # -------------------------------------------------------
    # Description
    # -------------------------------------------------------

    description: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True
    )

    # -------------------------------------------------------
    # Target
    # Example:
    # https://example.com
    # -------------------------------------------------------

    target: Mapped[str] = mapped_column(
        String(500),
        nullable=False
    )

    # -------------------------------------------------------
    # Current Status
    # -------------------------------------------------------

    status: Mapped[str] = mapped_column(
        String(50),
        default="created"
    )