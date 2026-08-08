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

import argparse
import logging
import sys

from dotenv import load_dotenv

from app.agents.manager_agent import ManagerAgent
from app.core.config import config
from app.core.logger import sentinel_logger
from app.database.base import Base
from app.database.connection import engine
from app.database.repositories.finding_repository import FindingRepository
from app.database.repositories.project_repository import ProjectRepository
from app.database.repositories.recon_result_repository import ReconResultRepository
from app.database.session import get_session
from app.services.finding_service import FindingService
from app.services.project_service import ProjectService
from app.services.recon_service import ReconService
from app.workflows.cli import CLI

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
# Logging Configuration
# ===========================================================


def setup_logging(debug: bool = False) -> None:
    """
    Configure logging for SentinelAI.

    Args:
        debug: Enable debug logging if True
    """
    # Set root logger level
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Configure SQLAlchemy logging - COMPLETELY SILENT in production
    if debug:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)
        logging.getLogger("sqlalchemy.pool").setLevel(logging.INFO)
        logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.INFO)
    else:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.ERROR)
        logging.getLogger("sqlalchemy.pool").setLevel(logging.ERROR)
        logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.ERROR)
        logging.getLogger("sqlalchemy.engine.base.Engine").setLevel(logging.ERROR)

    # Configure urllib3
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Configure scanner modules
    logging.getLogger("app.modules.scanner").setLevel(
        logging.DEBUG if debug else logging.INFO
    )
    logging.getLogger("app.services.recon_service").setLevel(
        logging.DEBUG if debug else logging.INFO
    )

    # Configure HTTP logging
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    if debug:
        print("[DEBUG] Logging mode: VERBOSE")
    else:
        print("[INFO] Logging mode: PRODUCTION")


# ===========================================================
# MAIN-005
# Main Application
# ===========================================================


def main() -> None:
    """
    Sentinel AI Entry Point
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="SentinelAI - Security Assessment Platform"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.debug)

    sentinel_logger.info("Starting Sentinel AI...")

    print("=" * 50)
    print(f"Project : {PROJECT_NAME}")
    print(f"Version : {VERSION}")
    print(f"Model   : {MODEL}")
    print("=" * 50)

    # Initialize Database - Silent
    Base.metadata.create_all(bind=engine)
    sentinel_logger.debug("Database initialized.")

    db = get_session()

    try:
        project_repo = ProjectRepository(db)
        recon_repo = ReconResultRepository(db)

        # Create Services
        project_service = ProjectService(project_repo)
        finding_repo = FindingRepository(db)
        finding_service = FindingService(finding_repo)
        recon_service = ReconService(recon_repo, finding_service)

        manager = ManagerAgent(project_service, recon_service)

        # ==========================================
        # Start Interactive CLI - No validator test
        # ==========================================

        cli = CLI(manager)
        cli.start()

    except KeyboardInterrupt:
        sentinel_logger.info("Shutdown requested by user")
    except Exception as e:
        sentinel_logger.exception(f"Application error: {e}")
        raise
    finally:
        db.close()

    sentinel_logger.info("Application shutdown complete.")


# ===========================================================
# MAIN-006
# Program Entry
# ===========================================================

if __name__ == "__main__":
    main()
