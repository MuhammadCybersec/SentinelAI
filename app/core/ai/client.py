# Ollama connection

"""
===========================================================
Project : Sentinel AI
Module  : AI Client
File ID : AI-CLIENT-001
Version : 0.0.1
===========================================================

Description:
Handles communication with the local Ollama server.

===========================================================
"""

# ===========================================================
# AI-CLIENT-001
# Imports
# ===========================================================

import ollama

from core.config import config
from core.logger import sentinel_logger

# ===========================================================
# AI-CLIENT-002
# AI Client Class
# ===========================================================

class AIClient:
    """
    Handles all communication with Ollama.
    """

    def __init__(self):
        """
        Initialize the AI client.
        """

        self.model = config.MODEL

        sentinel_logger.info(
            f"AI Client initialized with model: {self.model}"
        )

# ===========================================================
# AI-CLIENT-003
# Export AI Client
# ===========================================================

ai_client = AIClient()

"""
===========================================================
Changelog

0.0.1
- Initial AI client created.
===========================================================
"""