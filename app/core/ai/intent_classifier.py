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

Supported intents:

1.
User:
Create a project named OWASP Juice Shop with target https://demo.owasp-juice.shop

JSON:
{{
    "intent":"create_project",
    "name":"OWASP Juice Shop",
    "target":"https://demo.owasp-juice.shop",
    "description":"AI Test Project"
}}

2.
User:
list projects

JSON:
{{
    "intent":"list_projects"
}}

3.
User:
current project

JSON:
{{
    "intent":"current_project"
}}

4.
User:
current target

JSON:
{{
    "intent":"current_target"
}}

5.
User:
history

JSON:
{{
    "intent":"history"
}}

6.
User:
use project Tesla VRP

JSON:
{{
    "intent":"use_project",
    "name":"Tesla VRP"
}}

7.
User:
switch to project Google VRP

JSON:
{{
    "intent":"use_project",
    "name":"Google VRP"
}}

8.
User:
recon

JSON:
{{
    "intent":"recon"
}}

9.
User:
start recon

JSON:
{{
    "intent":"recon"
}}

10.
User:
scan target

JSON:
{{
    "intent":"recon"
}}



Now classify this command.

User:
{user_input}
"""

        response = ai_client.generate(prompt)

        sentinel_logger.info(response)

        try:
            return json.loads(response)

        except Exception:

            return {"intent": "unknown", "raw": response}
