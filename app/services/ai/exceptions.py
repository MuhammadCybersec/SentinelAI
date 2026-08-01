# =============================================================================
# FILE: app/services/ai/exceptions.py
# =============================================================================
# DESCRIPTION:
# Production-grade exception hierarchy for AI services in SentinelAI.
#
# This module provides a comprehensive exception hierarchy for all AI-related
# errors including configuration, connection, response, parsing, and provider errors.
# =============================================================================

import json
from typing import Any

# =============================================================================
# BASE EXCEPTION
# =============================================================================


class AIServiceError(Exception):
    """
    Base exception for all AI service errors.

    Attributes:
        message: Human-readable error message
        provider: Optional provider name (e.g., 'ollama', 'openai')
        model: Optional model identifier
        details: Optional additional error details
    """

    __slots__ = ("details", "message", "model", "provider")

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        model: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            provider: Optional provider name
            model: Optional model identifier
            details: Optional additional error details
        """
        self.message = message
        self.provider = provider
        self.model = model
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        """Return a formatted error message."""
        parts = [self.message]
        if self.provider is not None:
            parts.append(f"Provider: {self.provider}")
        if self.model is not None:
            parts.append(f"Model: {self.model}")
        if self.details:
            parts.append(f"Details: {json.dumps(self.details, indent=2)}")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert exception to structured dictionary.

        Returns:
            Dict[str, Any]: Structured error information
        """
        return {
            "type": self.__class__.__name__,
            "message": self.message,
            "provider": self.provider,
            "model": self.model,
            "details": self.details,
        }


# =============================================================================
# CONFIGURATION ERRORS
# =============================================================================


class AIConfigurationError(AIServiceError):
    """
    Raised when there is an issue with AI service configuration.

    Examples:
        - Missing required configuration
        - Invalid configuration values
        - Configuration file errors
    """


class AIModelError(AIServiceError):
    """
    Raised when there is an issue with the AI model itself.

    Examples:
        - Model loading failed
        - Model execution error
        - Model compatibility issues
    """


class AIModelNotFoundError(AIModelError):
    """
    Raised when a requested model is not found.

    Examples:
        - Model not installed
        - Model not available
        - Model ID invalid
    """


class AIModelDisabledError(AIModelError):
    """
    Raised when a requested model is disabled.

    Examples:
        - Model disabled by configuration
        - Model unavailable
        - Model not authorized
    """


# =============================================================================
# CONNECTION ERRORS
# =============================================================================


class AIConnectionError(AIServiceError):
    """
    Raised when unable to connect to the AI provider.

    Examples:
        - Network issues
        - Provider unreachable
        - Connection timeout
        - DNS resolution failed
    """


class AIRequestTimeoutError(AIConnectionError):
    """
    Raised when a request to the AI provider times out.

    Examples:
        - Request took too long
        - Provider slow to respond
        - Network latency
    """


# =============================================================================
# AUTHENTICATION ERRORS
# =============================================================================


class AIAuthenticationError(AIServiceError):
    """
    Raised when authentication with the AI provider fails.

    Examples:
        - Invalid API key
        - Expired credentials
        - Insufficient permissions
    """


# =============================================================================
# REQUEST ERRORS
# =============================================================================


class AIRequestError(AIServiceError):
    """
    Raised when a request to the AI provider fails.

    Examples:
        - Invalid request format
        - Request validation failed
        - Request rejected by provider
    """


class AIRateLimitError(AIRequestError):
    """
    Raised when rate limit is exceeded.

    Examples:
        - Too many requests
        - Quota exceeded
        - Throttling applied
    """


# =============================================================================
# RESPONSE ERRORS
# =============================================================================


class AIResponseError(AIServiceError):
    """
    Raised when the AI provider returns an error response.

    Examples:
        - Provider error response
        - Error in response payload
        - Unexpected error format
    """


class AIProviderError(AIServiceError):
    """
    Raised when the AI provider returns an error.

    Examples:
        - Provider-specific errors
        - Service unavailable
        - Internal server error
    """


# =============================================================================
# PARSING ERRORS
# =============================================================================


class AIParsingError(AIServiceError):
    """
    Raised when parsing AI response fails.

    Examples:
        - Invalid response format
        - Missing expected fields
        - Data type mismatch
    """


class ResponseParserError(AIParsingError):
    """
    Raised when the response parser fails.

    Examples:
        - Parser configuration error
        - Unsupported response format
        - Parser implementation error
    """


class InvalidJSONError(ResponseParserError):
    """
    Raised when response contains invalid JSON.

    Examples:
        - Malformed JSON
        - JSON syntax error
        - Incomplete JSON
    """


class EmptyResponseError(ResponseParserError):
    """
    Raised when response is empty.

    Examples:
        - Empty response body
        - Null response
        - No content
    """


class MalformedResponseError(ResponseParserError):
    """
    Raised when response is malformed.

    Examples:
        - Unexpected structure
        - Missing required elements
        - Invalid data types
    """


class MissingFieldError(ResponseParserError):
    """
    Raised when a required field is missing from the response.

    Examples:
        - Field not present
        - Field null
        - Field empty
    """


class InvalidFieldTypeError(ResponseParserError):
    """
    Raised when a field has an invalid type.

    Examples:
        - Type mismatch
        - Unexpected data type
        - Invalid enum value
    """


# =============================================================================
# PROMPT ERRORS
# =============================================================================


class PromptBuilderError(AIServiceError):
    """
    Raised when prompt building fails.

    Examples:
        - Template error
        - Variable substitution error
        - Invalid prompt format
    """


class PromptTemplateError(PromptBuilderError):
    """
    Raised when a prompt template is invalid.

    Examples:
        - Template not found
        - Invalid template syntax
        - Template validation failed
    """


class PromptValidationError(PromptBuilderError):
    """
    Raised when prompt validation fails.

    Examples:
        - Missing required variables
        - Invalid variable types
        - Unsafe content detected
    """


# =============================================================================
# SERVICE LAYER ERRORS (Re-exported from ai_service.py)
# =============================================================================


class ModelNotConfiguredError(AIServiceError):
    """
    Raised when no model is configured.

    Examples:
        - No active model set
        - Model configuration missing
    """


class PromptBuildError(AIServiceError):
    """
    Raised when prompt building fails.

    Examples:
        - Template not found
        - Missing variables
        - Invalid template
    """


class GenerationError(AIServiceError):
    """
    Raised when AI generation fails.

    Examples:
        - Model not configured
        - Client error
        - Timeout
    """


class ParseError(AIServiceError):
    """
    Raised when response parsing fails.

    Examples:
        - Invalid JSON
        - Empty response
        - Missing fields
    """
