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

        # ===========================================================

    # DB-REPOSITORY-003
    # List All Projects
    # ===========================================================

    def list_projects(self):
        """
        Return all projects.
        """

        return self.get_all(self.model)

    # ===========================================================
    # DB-REPOSITORY-004
    # Find Project By Name
    # ===========================================================

    def find_by_name(self, name: str):

        return (
            self.session.query(self.model).filter(self.model.name.ilike(name)).first()
        )
        # ===========================================================

    # Get Project By ID
    # ===========================================================

    def get_by_id(
        self,
        project_id: str,
    ):

        return (
            self.session.query(self.model)
            .filter(
                self.model.id == project_id,
            )
            .first()
        )

    # ===========================================================
    # Delete Project
    # ===========================================================

    def delete_project(
        self,
        project: Project,
    ) -> bool:

        self.session.delete(
            project,
        )

        self.session.commit()

        return True
        # ===========================================================

    # Update Project
    # ===========================================================

    def update_project(
        self,
        project: Project,
    ) -> Project:
        """
        Update an existing project.
        """

        self.session.commit()

        self.session.refresh(
            project,
        )

        return project

    # ===========================================================
    # Project Exists
    # ===========================================================

    def project_exists(
        self,
        name: str,
    ) -> bool:
        """
        Check whether a project already exists.
        """

        return (
            self.session.query(self.model)
            .filter(
                self.model.name.ilike(name),
            )
            .first()
            is not None
        )
