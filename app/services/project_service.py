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

        # =======================================================

    # DB-SERVICE-003
    # List Projects
    # =======================================================

    def list_projects(self):
        """
        Return all projects.
        """

        return self.repository.list_projects()

    # =======================================================
    # DB-SERVICE-004
    # Find Project
    # =======================================================

    def find_project(self, name: str):
        """
        Find a project by name.
        """

        return self.repository.find_by_name(name)

    # =======================================================
    # DB-SERVICE-003
    # Get Project By Name
    # =======================================================

    def get_project_by_name(self, name: str):

        return self.repository.find_by_name(name)

        # =======================================================

    # Get Project By ID
    # =======================================================

    def get_project_by_id(
        self,
        project_id: str,
    ):
        """
        Get project using ID.
        """

        return self.repository.get_by_id(
            project_id,
        )

    # =======================================================
    # Check Project Exists
    # =======================================================

    def project_exists(
        self,
        name: str,
    ) -> bool:
        """
        Check if project exists.
        """

        return self.repository.project_exists(
            name,
        )

    # =======================================================
    # Update Project
    # =======================================================

    def update_project(
        self,
        project: Project,
    ) -> Project:
        """
        Update project.
        """

        return self.repository.update_project(
            project,
        )
        # =======================================================

    # Delete Project
    # =======================================================

    def delete_project(
        self,
        project_id: str,
    ) -> bool:
        """
        Delete project by ID.
        """

        project = self.repository.get_by_id(
            project_id,
        )

        if project is None:
            return False

        return self.repository.delete_project(
            project,
        )

    # =======================================================
    # Create Project If Not Exists
    # =======================================================

    def create_project_if_not_exists(
        self,
        name: str,
        target: str,
        description: str = "",
    ) -> Project:
        """
        Create project only if it doesn't already exist.
        """

        existing = self.repository.find_by_name(
            name,
        )

        if existing:
            return existing

        return self.create_project(
            name=name,
            target=target,
            description=description,
        )


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Project Service Loaded Successfully")
    print("=" * 60)

    print()

    print("Methods Available:")

    print("- create_project()")
    print("- create_project_if_not_exists()")
    print("- list_projects()")
    print("- find_project()")
    print("- get_project_by_name()")
    print("- get_project_by_id()")
    print("- project_exists()")
    print("- update_project()")
    print("- delete_project()")
