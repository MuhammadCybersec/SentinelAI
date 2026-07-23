"""
===========================================================
Project : Sentinel AI
Module  : Base Repository
File ID : DB-REPOSITORY-001
Version : 0.0.1
===========================================================

Description:
Generic repository for all database models.

===========================================================
"""

# ===========================================================
# DB-REPOSITORY-001
# Imports
# ===========================================================

from typing import Generic, TypeVar

from sqlalchemy.orm import Session

# ===========================================================
# DB-REPOSITORY-002
# Generic Model Type
# ===========================================================

ModelType = TypeVar("ModelType")

# ===========================================================
# DB-REPOSITORY-003
# Base Repository
# ===========================================================


class BaseRepository(Generic[ModelType]):
    """
    Generic repository used by all database entities.
    """

    def __init__(self, session: Session):
        """
        Initialize repository.

        Args:
            session:
                SQLAlchemy Session
        """

        self.session = session

    # ===========================================================
    # DB-REPOSITORY-004
    # Create Entity
    # ===========================================================

    def create(self, entity: ModelType) -> ModelType:
        """
        Save a new entity into the database.
        """

        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)

        return entity

    # ===========================================================
    # DB-REPOSITORY-005
    # Get All Entities
    # ===========================================================

    def get_all(self, model):
        """
        Return all records of a model.
        """

        return self.session.query(model).all()

    # ===========================================================
    # DB-REPOSITORY-006
    # Get By ID
    # ===========================================================

    def get_by_id(self, model, entity_id):
        """
        Return a single entity by ID.
        """

        return self.session.query(model).filter(model.id == entity_id).first()
