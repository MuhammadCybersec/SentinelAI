"""
===========================================================
Project : Sentinel AI
Module  : Manager Agent
File ID : AGENT-MANAGER-001
Version : 0.0.1
===========================================================
"""

from app.core.logger import sentinel_logger
from app.services.project_service import ProjectService
from app.core.ai.intent_classifier import IntentClassifier


class ManagerAgent:
    """
    Main AI Agent responsible for handling user requests.
    """

    def __init__(self, project_service: ProjectService):

        self.project_service = project_service
        self.intent_classifier = IntentClassifier()

    def handle(self, command: str):

       data = self.intent_classifier.classify(command)

       if data["intent"] == "create_project":

        return self.project_service.create_project(

    name=data.get("name", "Untitled Project"),

    target=data.get("target", ""),

    description=data.get("description") or "No description provided"

)