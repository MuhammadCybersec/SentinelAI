"""
===========================================================
Project : Sentinel AI
Module  : Memory Agent
File ID : MEMORY-AGENT-001
Version : 0.1.0
===========================================================

Description:
Handles all interactions with Session Memory.

===========================================================
"""

# ===========================================================
# MEMORY-AGENT-001
# Imports
# ===========================================================

from app.modules.memory.session_memory import memory

# ===========================================================
# MEMORY-AGENT-002
# Memory Agent
# ===========================================================


class MemoryAgent:
    """
    Agent responsible for reading and writing session memory.
    """

    def remember_project(self, project):
        """
        Save current project into memory.
        """

        memory.set_project(project)

    def current_project(self):
        """
        Return current project.
        """

        return memory.get_project()

    def remember_target(self, target):
        """
        Save current target.
        """

        memory.set_target(target)

    def current_target(self):
        """
        Return current target.
        """

        return memory.get_target()

    def remember_intent(self, intent):
        """
        Save last AI intent.
        """

        memory.set_intent(intent)

    def current_intent(self):
        """
        Return last AI intent.
        """

        return memory.get_intent()

    def add_history(self, command):
        """
        Save command into history.
        """

        memory.add_history(command)

    def history(self):
        """
        Return conversation history.
        """

        return memory.get_history()


# ===========================================================
# MEMORY-AGENT-003
# Global Memory Agent
# ===========================================================

memory_agent = MemoryAgent()
