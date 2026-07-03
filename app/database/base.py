"""
===========================================================
Project : Sentinel AI
Module  : Database Base
File ID : DB-BASE-001
Version : 0.0.1
===========================================================

Description:
Defines the SQLAlchemy Declarative Base for all database models.

===========================================================
"""

# ===========================================================
# DB-BASE-001
# Imports
# ===========================================================

from sqlalchemy.orm import DeclarativeBase

# ===========================================================
# DB-BASE-002
# Base Class
# ===========================================================

class Base(DeclarativeBase):
    """
    Base class inherited by every database model.
    """
    pass

"""
===========================================================
Changelog

0.0.1
- Initial SQLAlchemy Base class created.
===========================================================
"""