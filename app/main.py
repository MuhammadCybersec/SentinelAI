"""
===========================================================
Project : Sentinel AI
Module  : Main Entry Point
File ID : MAIN-001
Version : 0.0.1
===========================================================

Description:
Application entry point for Sentinel AI.
===========================================================
"""

# ===========================================================
# MAIN-001
# Imports
# ===========================================================

from dotenv import load_dotenv

from app.core.logger import sentinel_logger
from app.core.config import config

from app.database.base import Base
from app.database.connection import engine
from app.database.session import get_session

from app.database.repositories.project_repository import ProjectRepository
from app.services.project_service import ProjectService

from app.agents.manager_agent import ManagerAgent
from app.workflows.cli import CLI

from app.modules.recon import TargetValidator
from app.services.recon_service import ReconService
from app.database.repositories.recon_result_repository import ReconResultRepository
from app.database.repositories.finding_repository import FindingRepository
from app.services.finding_service import FindingService

# ===========================================================
# MAIN-002
# Load Environment Variables
# ===========================================================

load_dotenv()

# ===========================================================
# MAIN-003
# Read Configuration
# ===========================================================

PROJECT_NAME = config.PROJECT_NAME
VERSION = config.VERSION
MODEL = config.MODEL

# ===========================================================
# MAIN-004
# Main Application
# ===========================================================


def main() -> None:
    """
    Sentinel AI Entry Point
    """

    sentinel_logger.info("Starting Sentinel AI...")

    print("=" * 50)
    print(f"Project : {PROJECT_NAME}")
    print(f"Version : {VERSION}")
    print(f"Model   : {MODEL}")
    print("=" * 50)

    # Initialize Database
    Base.metadata.create_all(bind=engine)

    print("Database tables created successfully.")

    db = get_session()

    try:

        project_repo = ProjectRepository(db)

        recon_repo = ReconResultRepository(db)

        # ==========================================
        # Create Manager Agent
        # ==========================================

        project_service = ProjectService(project_repo)
        finding_repo = FindingRepository(db)
        finding_service = FindingService(
            finding_repo,
        )
        recon_service = ReconService(
            recon_repo,
            finding_service,
        )

        manager = ManagerAgent(
            project_service,
            recon_service,
        )

        # ==========================================
        # Recon Validator Test
        # ==========================================

        print("\nRecon Validator Test")
        print("-" * 40)

        print(
            "https://bugcrowd.com :", TargetValidator.is_valid("https://bugcrowd.com")
        )

        print("bugcrowd.com :", TargetValidator.is_valid("bugcrowd.com"))

        print("hello world :", TargetValidator.is_valid("hello world"))

        # ==========================================
        # Start Interactive CLI
        # ==========================================

        cli = CLI(manager)

        cli.start()

    except Exception as e:

        sentinel_logger.exception(e)

    finally:

        db.close()

    sentinel_logger.success("Application started successfully.")


# ===========================================================
# MAIN-005
# Program Entry
# ===========================================================

if __name__ == "__main__":
    main()
