"""
===========================================================
Project : Sentinel AI
Module  : AI Service
File ID : AI-SERVICE-001
Version : 0.1.0
===========================================================

Description:
High-level AI service used by SentinelAI agents.

This service wraps AIClient and provides reusable methods
for planning, analysis, summarization and explanation.

Agents should NEVER communicate with AIClient directly.

===========================================================
"""

from __future__ import annotations

from app.core.ai.client import ai_client
from app.core.logger import sentinel_logger


class AIService:
    """
    High-level interface for all AI interactions.
    """

    def chat(self, prompt: str) -> str:
        """
        Send a prompt to the configured AI model.

        Args:
            prompt:
                User prompt.

        Returns:
            Model response.
        """

        sentinel_logger.info("AIService.chat()")

        return ai_client.generate(prompt)

    def plan(self, prompt: str) -> str:
        """
        Generate an execution plan.
        """

        sentinel_logger.info("AIService.plan()")

        return self.chat(prompt)

    def analyze(self, prompt: str) -> str:
        """
        Analyze scanner results.
        """

        sentinel_logger.info("AIService.analyze()")

        return self.chat(prompt)

    def summarize(self, prompt: str) -> str:
        """
        Summarize findings.
        """

        sentinel_logger.info("AIService.summarize()")

        return self.chat(prompt)

    def explain(self, prompt: str) -> str:
        """
        Explain vulnerabilities.
        """

        sentinel_logger.info("AIService.explain()")

        return self.chat(prompt)

    def generate_payload(self, prompt: str) -> str:
        """
        Generate payload suggestions.
        """

        sentinel_logger.info("AIService.generate_payload()")

        return self.chat(prompt)


ai_service = AIService()
