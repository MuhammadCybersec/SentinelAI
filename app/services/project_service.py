"""
===========================================================
Project : Sentinel AI
Module  : Project Service
File ID : DB-SERVICE-001
Version : 0.0.1
===========================================================

Description:
Business logic for Project operations.

===========================================================
"""

# ===========================================================
# DB-SERVICE-001
# Imports
# ===========================================================

from app.database.models.project import Project
from app.database.repositories.project_repository import ProjectRepository


class ProjectService:
    """
    Handles project business logic.
    """

    def __init__(self, repository: ProjectRepository):
        """
        Initialize service.

        Args:
            repository:
                Project repository.
        """
        self.repository = repository

    # =======================================================
    # DB-SERVICE-002
    # Create Project
    # =======================================================

    def create_project(
        self,
        name: str,
        target: str,
        description: str = "",
    ) -> Project:
        """
        Create a new project.
        """

        project = Project(
            name=name,
            target=target,
            description=description,
            status="created",
        )

        return self.repository.create(project)