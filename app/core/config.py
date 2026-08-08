"""
===========================================================
Project : Sentinel AI
Module  : Configuration Manager
File ID : CONFIG-001
Version : 0.0.1
===========================================================

Description:
Loads and validates project configuration from .env.

===========================================================
"""

# ===========================================================
# CONFIG-001
# Imports
# ===========================================================

import os

from dotenv import load_dotenv

# ===========================================================
# CONFIG-002
# Load Environment Variables
# ===========================================================

load_dotenv()

# ===========================================================
# CONFIG-003
# Configuration Class
# ===========================================================


class Config:
    """
    Central configuration for Sentinel AI.
    """

    # Project Settings
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "SentinelAI")
    VERSION: str = os.getenv("VERSION", "0.0.1")
    MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # Database Settings
    DATABASE_TYPE: str = os.getenv("DATABASE_TYPE", "sqlite")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "sentinel.db")
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "data/sentinel.db")

    # ==========================================================
    # Scanner Settings
    # ==========================================================

    VERBOSE_MODE: bool = os.getenv("VERBOSE_MODE", "False").lower() == "true"

    SCANNER_TIMEOUT: int = int(os.getenv("SCANNER_TIMEOUT", "30"))
    SCANNER_MAX_PAYLOADS: int = int(os.getenv("SCANNER_MAX_PAYLOADS", "50"))
    SCANNER_REQUEST_DELAY: float = float(os.getenv("SCANNER_REQUEST_DELAY", "0.1"))

    # ==========================================================
    # Confidence Scoring Settings
    # ==========================================================

    CONFIDENCE_THRESHOLD_VERIFIED: float = float(
        os.getenv("CONFIDENCE_THRESHOLD_VERIFIED", "70.0")
    )
    CONFIDENCE_CRITICAL_MIN: float = float(os.getenv("CONFIDENCE_CRITICAL_MIN", "90.0"))
    CONFIDENCE_HIGH_MIN: float = float(os.getenv("CONFIDENCE_HIGH_MIN", "70.0"))
    CONFIDENCE_MEDIUM_MIN: float = float(os.getenv("CONFIDENCE_MEDIUM_MIN", "40.0"))

    # ==========================================================
    # Deduplication Settings
    # ==========================================================

    DEDUPLICATION_ENABLED: bool = (
        os.getenv("DEDUPLICATION_ENABLED", "True").lower() == "true"
    )

    # ==========================================================
    # Reporting Settings
    # ==========================================================

    SHOW_FINDINGS_IN_TERMINAL: bool = (
        os.getenv("SHOW_FINDINGS_IN_TERMINAL", "False").lower() == "true"
    )

    # ==========================================================
    # Scope & Safety Settings (ADD THIS SECTION)
    # ==========================================================

    SCOPE_ENABLED: bool = os.getenv("SCOPE_ENABLED", "True").lower() == "true"
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_REQUESTS_PER_SECOND: float = float(
        os.getenv("RATE_LIMIT_REQUESTS_PER_SECOND", "1.0")
    )
    MAX_URLS: int = int(os.getenv("MAX_URLS", "1000"))
    MAX_REQUESTS: int = int(os.getenv("MAX_REQUESTS", "5000"))
    DRY_RUN: bool = os.getenv("DRY_RUN", "False").lower() == "true"

    # ==========================================================
    # Methods
    # ==========================================================

    def is_verbose(self) -> bool:
        """Check if verbose mode is enabled."""
        return self.VERBOSE_MODE or self.DEBUG

    def get_confidence_level(self, score: float) -> str:
        """Get confidence level string from score."""
        if score >= self.CONFIDENCE_CRITICAL_MIN:
            return "Critical"
        elif score >= self.CONFIDENCE_HIGH_MIN:
            return "High"
        elif score >= self.CONFIDENCE_MEDIUM_MIN:
            return "Medium"
        else:
            return "Low"

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "PROJECT_NAME": self.PROJECT_NAME,
            "VERSION": self.VERSION,
            "MODEL": self.MODEL,
            "DEBUG": self.DEBUG,
            "VERBOSE_MODE": self.VERBOSE_MODE,
            "DATABASE_PATH": self.DATABASE_PATH,
            "SCANNER_TIMEOUT": self.SCANNER_TIMEOUT,
            "CONFIDENCE_THRESHOLD_VERIFIED": self.CONFIDENCE_THRESHOLD_VERIFIED,
            "DEDUPLICATION_ENABLED": self.DEDUPLICATION_ENABLED,
            "SCOPE_ENABLED": self.SCOPE_ENABLED,
            "RATE_LIMIT_ENABLED": self.RATE_LIMIT_ENABLED,
            "RATE_LIMIT_REQUESTS_PER_SECOND": self.RATE_LIMIT_REQUESTS_PER_SECOND,
            "MAX_URLS": self.MAX_URLS,
            "MAX_REQUESTS": self.MAX_REQUESTS,
            "DRY_RUN": self.DRY_RUN,
        }


# ===========================================================
# CONFIG-004
# Export Config
# ===========================================================

config = Config()

# ===========================================================
# CONFIG-005
# Convenience Functions
# ===========================================================


def get_config() -> Config:
    """Get the global config instance."""
    return config


def set_verbose_mode(enabled: bool = True) -> None:
    """Enable or disable verbose mode at runtime."""
    config.VERBOSE_MODE = enabled


def is_verbose() -> bool:
    """Check if verbose mode is enabled."""
    return config.is_verbose()


"""
===========================================================
Changelog

0.0.1 - Initial configuration manager.
0.0.2 - Added scanner settings (VERBOSE_MODE, timeout, etc.)
       - Added confidence scoring settings
       - Added deduplication settings
       - Added reporting settings
       - Added convenience functions
0.0.3 - Added scope & safety settings (SCOPE_ENABLED, RATE_LIMIT_ENABLED, etc.)
===========================================================
"""
