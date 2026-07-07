"""
===========================================================
Project : Sentinel AI
Module  : Intent Classifier
File ID : AI-INTENT-001
Version : 0.0.1
===========================================================
"""

import json

from app.core.ai.client import ai_client
from app.core.logger import sentinel_logger


class IntentClassifier:
    """
    Uses Llama3 to classify user commands.
    """

    def classify(self, user_input: str) -> dict:

        prompt = f"""
You are an AI Intent Classifier.

Return ONLY valid JSON.

Example:

{{
    "intent":"create_project",
    "name":"OWASP Juice Shop",
    "target":"https://demo.owasp-juice.shop",
    "description":"AI Test Project"
}}

User:

{user_input}
"""

        response = ai_client.generate(prompt)

        sentinel_logger.info(response)

        try:
            return json.loads(response)

        except Exception:

            return {

                "intent": "unknown",

                "raw": response

            }