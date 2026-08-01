"""
===========================================================
Project : Sentinel AI
Module  : Database Connection
File ID : DB-CONNECTION-001
Version : 0.0.1
===========================================================

Description:
Creates and manages the SQLAlchemy engine.

===========================================================
"""

# ===========================================================
# DB-CONNECTION-001
# Imports
# ===========================================================

from sqlalchemy import create_engine

from app.core.config import config
from app.core.logger import sentinel_logger

# ===========================================================
# DB-CONNECTION-002
# Build SQLite Connection String
# ===========================================================

DATABASE_URL = f"sqlite:///{config.DATABASE_PATH}"

# ===========================================================
# DB-CONNECTION-003
# Create Engine
# ===========================================================

engine = create_engine(DATABASE_URL, echo=config.DEBUG, future=True)

# ===========================================================
# DB-CONNECTION-004
# Log Success
# ===========================================================

sentinel_logger.success("Database Engine Initialized.")
