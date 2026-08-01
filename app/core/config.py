"""
===========================================================
Project : Sentinel AI
Module  : Configuration Manager
File ID : CONFIG-001
Version : 0.0.1
===========================================================

Description:
Loads and validates project configuration from .env.

===========================================================
"""

# ===========================================================
# CONFIG-001
# Imports
# ===========================================================

import os

from dotenv import load_dotenv

# ===========================================================
# CONFIG-002
# Load Environment Variables
# ===========================================================

load_dotenv()

# ===========================================================
# CONFIG-003
# Configuration Class
# ===========================================================


class Config:
    """
    Central configuration for Sentinel AI.
    """

    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "SentinelAI")
    VERSION: str = os.getenv("VERSION", "0.0.1")
    MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    DATABASE_TYPE: str = os.getenv("DATABASE_TYPE", "sqlite")

    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "sentinel.db")
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "data/sentinel.db")


# ===========================================================
# CONFIG-004
# Export Config
# ===========================================================

config = Config()

"""
===========================================================
Changelog

0.0.1
- Initial configuration manager.
===========================================================
"""
