"""
===========================================================
Project : Sentinel AI
Module  : Target Validator
File ID : RECON-VALIDATOR-001
Version : 0.1.0
===========================================================

Description:
Validates user supplied reconnaissance targets.
===========================================================
"""

# ===========================================================
# Imports
# ===========================================================

from urllib.parse import urlparse


class TargetValidator:
    """
    Validate reconnaissance targets.
    """

    @staticmethod
    def is_valid(target: str) -> bool:
        """
        Returns True if target is a valid HTTP/HTTPS URL.
        """

        if not target:
            return False

        try:
            parsed = urlparse(target)

            return parsed.scheme in ("http", "https") and parsed.netloc != ""

        except Exception:
            return False
