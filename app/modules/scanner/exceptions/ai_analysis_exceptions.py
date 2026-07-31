"""
Exceptions for AI Analysis Service.
"""

from typing import Optional, Dict, Any


class ScannerAIAnalysisError(Exception):
    """
    Base exception for AI analysis service errors.

    Attributes:
        message: Human-readable error message
        details: Additional error details
    """

    __slots__ = ("message", "details")

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class ScannerAINotConfiguredError(ScannerAIAnalysisError):
    """Raised when AI service is not configured."""

    pass


class ScannerAIConnectionError(ScannerAIAnalysisError):
    """Raised when connection to AI service fails."""

    pass


class ScannerAIParsingError(ScannerAIAnalysisError):
    """Raised when parsing AI response fails."""

    pass


class ScannerAIReportError(ScannerAIAnalysisError):
    """Raised when generating AI report fails."""

    pass
