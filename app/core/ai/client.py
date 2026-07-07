"""
===========================================================
Project : Sentinel AI
Module  : AI Client
File ID : AI-CLIENT-001
Version : 0.0.2
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

from app.core.config import config
from app.core.logger import sentinel_logger


# ===========================================================
# AI-CLIENT-002
# AI Client Class
# ===========================================================

class AIClient:
    """
    Handles all communication with Ollama.
    """

    def __init__(self):

        self.model = config.MODEL

        sentinel_logger.info(
            f"AI Client initialized with model: {self.model}"
        )

    # =======================================================
    # AI-CLIENT-003
    # Generate Response
    # =======================================================

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to Ollama and return the response.
        """

        try:

            response = ollama.chat(

                model=self.model,

                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]

            )

            return response["message"]["content"]

        except Exception as e:

            sentinel_logger.exception(e)

            return ""


# ===========================================================
# AI-CLIENT-004
# Export AI Client
# ===========================================================

ai_client = AIClient()