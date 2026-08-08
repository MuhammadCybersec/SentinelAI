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

import logging
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
# Create Engine - NO SQL LOGS in production
# ===========================================================

# echo=False - hides SQL queries in production
# echo=config.DEBUG - shows SQL queries only in debug mode
engine = create_engine(
    DATABASE_URL,
    echo=config.DEBUG,  # Only show SQL in debug mode
    future=True,
)

# ===========================================================
# DB-CONNECTION-004
# Log Success (silent in production)
# ===========================================================

if config.DEBUG:
    sentinel_logger.debug("Database Engine Initialized.")
else:
    # Silent - no output
    pass
