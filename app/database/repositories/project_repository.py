"""
===========================================================
Project : Sentinel AI
Module  : Project Repository
File ID : DB-REPOSITORY-002
Version : 0.0.1
===========================================================
"""

from sqlalchemy.orm import Session

from app.database.models.project import Project
from app.database.repositories.base_repository import BaseRepository


class ProjectRepository(BaseRepository[Project]):
    """
    Repository for Project model.
    """

    def __init__(self, session: Session):
        super().__init__(session)
        self.model = Project