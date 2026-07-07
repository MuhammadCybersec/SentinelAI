"""
===========================================================
Project : Sentinel AI
Module  : Database Session Manager
File ID : DB-SESSION-001
Version : 0.0.1
===========================================================

Description:
Creates SQLAlchemy session factory and session helper.

===========================================================
"""

# ===========================================================
# DB-SESSION-001
# Imports
# ===========================================================

from sqlalchemy.orm import sessionmaker

from app.database.connection import engine

# ===========================================================
# DB-SESSION-002
# Session Factory
# ===========================================================

SessionLocal = sessionmaker(

    bind=engine,

    autoflush=False,

    autocommit=False,

    expire_on_commit=False

)

# ===========================================================
# DB-SESSION-003
# Session Provider
# ===========================================================

def get_session():
    """
    Create and return a new database session.

    Returns:
        Session
    """

    return SessionLocal()