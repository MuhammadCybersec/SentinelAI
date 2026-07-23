"""
===========================================================
Project : Sentinel AI
Module  : Session Memory
File ID : MEMORY-001
Version : 0.1.0
===========================================================

Description:
Stores the current runtime session information.

===========================================================
"""

# ===========================================================
# MEMORY-001
# Session Memory Class
# ===========================================================

class SessionMemory:
    """
    Stores runtime information for the current session.
    """

    def __init__(self):
        """
        Initialize memory.
        """

        self.current_project = None
        self.current_target = None
        self.last_intent = None
        self.history = []

    # =======================================================
    # MEMORY-002
    # Set Current Project
    # =======================================================

    def set_project(self, project):

        self.current_project = project

    # =======================================================
    # MEMORY-003
    # Get Current Project
    # =======================================================

    def get_project(self):

        return self.current_project

    # =======================================================
    # MEMORY-004
    # Set Current Target
    # =======================================================

    def set_target(self, target):

        self.current_target = target

    # =======================================================
    # MEMORY-005
    # Get Current Target
    # =======================================================

    def get_target(self):

        return self.current_target

    # =======================================================
    # MEMORY-006
    # Save Last Intent
    # =======================================================

    def set_intent(self, intent):

        self.last_intent = intent

    # =======================================================
    # MEMORY-007
    # Get Last Intent
    # =======================================================

    def get_intent(self):

        return self.last_intent

    # =======================================================
    # MEMORY-008
    # Save Conversation History
    # =======================================================

    def add_history(self, command):

        self.history.append(command)

    # =======================================================
    # MEMORY-009
    # Get Conversation History
    # =======================================================

    def get_history(self):

        return self.history


# ===========================================================
# MEMORY-010
# Global Session Memory Object
# ===========================================================

memory = SessionMemory()