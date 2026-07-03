"""
===========================================================
Project : Sentinel AI
Module  : Main Entry Point
File ID : MAIN-001
Version : 0.0.1
===========================================================

Description:
This is the application's main entry point.
It verifies that the project is running correctly.

===========================================================
"""

# ===========================================================
# MAIN-001
# Import required libraries
# ===========================================================

from dotenv import load_dotenv
import os

from core.logger import sentinel_logger
from core.config import config
from core.ai.client import ai_client


# ===========================================================
# MAIN-002
# Load environment variables
# ===========================================================

load_dotenv()

# ===========================================================
# MAIN-009
# Read project configuration
# ===========================================================

PROJECT_NAME = config.PROJECT_NAME
VERSION = config.VERSION
MODEL = config.MODEL

# ===========================================================
# MAIN-004
# Application starting point
# ===========================================================

def main():
    """
    Start Sentinel AI.
    """
    sentinel_logger.info("Starting Sentinel AI...")

    print("=" * 50)
    print(f"Project : {PROJECT_NAME}")
    print(f"Version : {VERSION}")
    print(f"Model   : {MODEL}")
    print("=" * 50)
    print("Sentinel AI Started Successfully ✅")

    sentinel_logger.success("Application started successfully.")
# ===========================================================
# MAIN-005
# Run application
# ===========================================================

if __name__ == "__main__":
    main()

"""
===========================================================
Changelog

0.0.1
- Initial application created.
===========================================================
"""