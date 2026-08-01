"""
===========================================================
Project : Sentinel AI
Module  : API Dependencies
File ID : API-DEP-001
Version : 1.0.0
===========================================================

Description:
Dependency injection for FastAPI.

===========================================================
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.database.repositories.finding_repository import (
    FindingRepository,
)
from app.database.repositories.project_repository import (
    ProjectRepository,
)
from app.database.session import SessionLocal
from app.modules.dashboard.dashboard_engine import (
    DashboardEngine,
)
from app.modules.dashboard.statistics_engine import (
    StatisticsEngine,
)
from app.modules.vulnerability.evidence_manager import (
    EvidenceManager,
)
from app.modules.vulnerability.finding_manager import (
    FindingManager,
)
from app.modules.vulnerability.notes_manager import (
    NotesManager,
)
from app.modules.vulnerability.search_engine import (
    SearchEngine,
)
from app.modules.vulnerability.status_engine import (
    StatusEngine,
)
from app.modules.vulnerability.tags_manager import (
    TagsManager,
)
from app.services.finding_service import (
    FindingService,
)
from app.services.project_service import (
    ProjectService,
)

# ===========================================================
# Database Session
# ===========================================================


def get_db() -> Generator[Session, None, None]:
    """
    Provide database session.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ===========================================================
# Repository
# ===========================================================


def get_finding_repository(
    db: Session,
) -> FindingRepository:
    """
    Create Finding Repository.
    """

    return FindingRepository(
        db,
    )


# ===========================================================
# Service
# ===========================================================


def get_finding_service(
    db: Session,
) -> FindingService:
    """
    Create Finding Service.
    """

    repository = get_finding_repository(
        db,
    )

    return FindingService(
        repository,
    )


# ===========================================================
# Manager
# ===========================================================


def get_finding_manager(
    db: Session,
) -> FindingManager:
    """
    Create Finding Manager.
    """

    service = get_finding_service(
        db,
    )

    return FindingManager(
        service,
    )


# ===========================================================
# Project Repository
# ===========================================================


def get_project_repository(
    db: Session,
) -> ProjectRepository:

    return ProjectRepository(
        db,
    )


# ===========================================================
# Project Service
# ===========================================================


def get_project_service(
    db: Session,
) -> ProjectService:

    repository = get_project_repository(
        db,
    )

    return ProjectService(
        repository,
    )


# ===========================================================
# Statistics Engine
# ===========================================================


def get_statistics_engine() -> StatisticsEngine:
    """
    Create Statistics Engine.
    """

    return StatisticsEngine()


# ===========================================================
# Dashboard Engine
# ===========================================================


def get_dashboard_engine() -> DashboardEngine:
    """
    Create Dashboard Engine.
    """

    return DashboardEngine()


# ===========================================================
# Search Engine
# ===========================================================


def get_search_engine() -> SearchEngine:
    """
    Create Search Engine.
    """

    return SearchEngine()


# ===========================================================
# Status Engine
# ===========================================================


def get_status_engine() -> StatusEngine:
    """
    Create Status Engine.
    """

    return StatusEngine()


# ===========================================================
# Notes Manager
# ===========================================================


def get_notes_manager() -> NotesManager:
    """
    Create Notes Manager.
    """

    return NotesManager()


# ===========================================================
# Tags Manager
# ===========================================================


def get_tags_manager() -> TagsManager:
    """
    Create Tags Manager.
    """

    return TagsManager()


# ===========================================================
# Evidence Manager
# ===========================================================


def get_evidence_manager() -> EvidenceManager:
    """
    Create Evidence Manager.
    """

    return EvidenceManager()


# ===========================================================
# Dependency Container
# ===========================================================


def get_dependencies() -> dict:
    """
    Return all shared dependencies.
    """

    return {
        "statistics": get_statistics_engine(),
        "dashboard": get_dashboard_engine(),
        "search": get_search_engine(),
        "status": get_status_engine(),
        "notes": get_notes_manager(),
        "tags": get_tags_manager(),
        "evidence": get_evidence_manager(),
    }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Dependencies Test")
    print("=" * 60)

    deps = get_dependencies()

    print()

    for name, dependency in deps.items():
        print(f"{name:15} -> {dependency.__class__.__name__}")

    print()

    print("Dependency container initialized successfully.")
