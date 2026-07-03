"""
===========================================================
Project : Sentinel AI
Module  : Logger
File ID : LOGGER-001
Version : 0.0.1
===========================================================

Description:
This module creates the application's logger.

===========================================================
"""

# ===========================================================
# LOGGER-001
# Import required libraries
# ===========================================================

import os
import sys

from loguru import logger

# ===========================================================
# LOGGER-002
# Create logs directory if it doesn't exist
# ===========================================================

os.makedirs("logs", exist_ok=True)

# ===========================================================
# LOGGER-003
# Remove default logger
# ===========================================================

logger.remove()

# ===========================================================
# LOGGER-004
# Console Logger
# ===========================================================

logger.add(
    sys.stdout,
    level="INFO",
    colorize=True,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>"
)

# ===========================================================
# LOGGER-005
# File Logger
# ===========================================================

logger.add(
    "logs/sentinel.log",
    level="DEBUG",
    rotation="10 MB",
    retention="30 days",
    encoding="utf-8"
)

# ===========================================================
# LOGGER-006
# Export Logger
# ===========================================================

sentinel_logger = logger

"""
===========================================================
Changelog

0.0.1
- Logger created.

===========================================================
"""