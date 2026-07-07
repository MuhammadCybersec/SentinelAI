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

        repo = ProjectRepository(db)

        service = ProjectService(repo)

                # ==========================================
        # Create Manager Agent
        # ==========================================

        manager = ManagerAgent(service)

        # ==========================================
        # Send Command to AI Manager
        # ==========================================

        result = manager.handle(
            "Create a project named OWASP Juice Shop with target https://demo.owasp-juice.shop"
        )

        # ==========================================
        # Print Result
        # ==========================================

        print("\nProject Created Successfully")
        print("-" * 40)
        print(f"ID          : {result.id}")
        print(f"Name        : {result.name}")
        print(f"Target      : {result.target}")
        print(f"Description : {result.description}")

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