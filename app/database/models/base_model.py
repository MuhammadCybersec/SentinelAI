"""
===========================================================
Project : Sentinel AI
Module  : Base Database Model
File ID : DB-MODEL-001
Version : 0.0.1
===========================================================

Description:
Common base model inherited by all ORM models.

===========================================================
"""

# ===========================================================
# DB-MODEL-001
# Imports
# ===========================================================

import uuid

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.base import Base

# ===========================================================
# DB-MODEL-002
# Base Model
# ===========================================================

class BaseModel(Base):
    """
    Base model for every database entity.
    """

    __abstract__ = True

    id: Mapped[str] = mapped_column(
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )