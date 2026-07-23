"""
===========================================================
Project : Sentinel AI
Module  : Manager Agent
File ID : AGENT-MANAGER-001
Version : 0.0.1
===========================================================
"""

from app.services.project_service import ProjectService
from app.core.ai.intent_classifier import IntentClassifier
from app.agents.memory_agent import memory_agent
from app.agents.recon_agent import recon_agent
from app.services.recon_service import ReconService


class ManagerAgent:
    """
    Main AI Agent responsible for handling user requests.
    """

    def __init__(
        self,
        project_service: ProjectService,
        recon_service: ReconService,
    ):

        self.project_service = project_service
        self.recon_service = recon_service
        self.intent_classifier = IntentClassifier()

    def handle(self, command: str):
        """
        Handle user command.
        """

        command_lower = command.lower().strip()

        # ==========================================================
        # FAST COMMANDS (No AI Required)
        # ==========================================================

        if command_lower in ["recon", "start recon", "scan target"]:

            project = memory_agent.current_project()

            if project is None:
                return "No active project."

            return self.recon_service.run(
                project.id,
                project.target,
            )

        # ==========================================================
        # MEMORY COMMANDS
        # ==========================================================

        if command_lower == "current project":

            project = memory_agent.current_project()

            if project is None:
                return "No active project."

            return project

        if command_lower == "current target":

            target = memory_agent.current_target()

            if target is None:
                return "No active target."

            return target

        if command_lower == "history":

            return memory_agent.history()

        # ==========================================================
        # AI Intent Classification
        # ==========================================================

        data = self.intent_classifier.classify(command)

        # ==========================================================
        # Create Project
        # ==========================================================

        if data.get("intent") == "create_project":

            project = self.project_service.create_project(
                name=data.get("name", "Untitled Project"),
                target=data.get("target", ""),
                description=data.get("description") or "No description provided",
            )

            memory_agent.remember_project(project)
            memory_agent.remember_target(project.target)
            memory_agent.remember_intent(data.get("intent"))
            memory_agent.add_history(command)

            return project

        # ==========================================================
        # Use Existing Project
        # ==========================================================

        if data.get("intent") == "use_project":

            project = self.project_service.get_project_by_name(data.get("name", ""))

            if project is None:
                return "Project not found."

            memory_agent.remember_project(project)
            memory_agent.remember_target(project.target)
            memory_agent.remember_intent("use_project")
            memory_agent.add_history(command)

            return f"Active project changed to: {project.name}"

            # ==========================================================
        # List Projects
        # ==========================================================

        if command_lower == "list projects":

            return self.project_service.list_projects()

            # ==========================================================
        # Recon
        # ==========================================================

        if data.get("intent") == "recon":

            project = memory_agent.current_project()

            if project is None:
                return "No active project."

            return self.recon_service.run(
                project.id,
                project.target,
            )

        # ==========================================================
        # Unknown Command
        # ==========================================================

        return "Unknown command."
