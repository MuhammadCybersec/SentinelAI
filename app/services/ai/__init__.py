# =============================================================================
# FILE: app/services/ai/__init__.py
# =============================================================================
# DESCRIPTION:
# AI Service package initializer for SentinelAI.
#
# This package provides a comprehensive AI service layer including:
# - AIService: Main orchestration layer
# - AIClient: AI provider communication
# - ModelManager: Model configuration management
# - PromptBuilder: Prompt construction
# - ResponseParser: AI response parsing
# - Exceptions: Complete exception hierarchy
# =============================================================================

# =============================================================================
# EXCEPTIONS - Import first to avoid circular imports
# =============================================================================
from app.services.ai.exceptions import (
    AIServiceError,
    AIConfigurationError,
    AIConnectionError,
    AIResponseError,
    AIProviderError,
    AIModelError,
    AIModelNotFoundError,
    AIModelDisabledError,
    AIRequestError,
    AIRequestTimeoutError,
    AIRateLimitError,
    AIAuthenticationError,
    AIParsingError,
    ResponseParserError,
    InvalidJSONError,
    EmptyResponseError,
    MalformedResponseError,
    MissingFieldError,
    InvalidFieldTypeError,
    PromptBuilderError,
    PromptTemplateError,
    PromptValidationError,
    ModelNotConfiguredError,
    PromptBuildError,
    GenerationError,
    ParseError,
)

# =============================================================================
# SERVICE LAYER
# =============================================================================
from app.services.ai.ai_service import (
    AIService,
)

# =============================================================================
# CLIENT LAYER
# =============================================================================
from app.services.ai.ai_client import (
    AIClient,
    AIClientError,
)

# =============================================================================
# MODEL MANAGEMENT
# =============================================================================
from app.services.ai.model_manager import (
    ModelManager,
    ModelConfig,
    ModelProvider,
)

# =============================================================================
# PROMPT BUILDER
# =============================================================================
from app.services.ai.prompt_builder import (
    PromptBuilder,
    PromptTemplate,
    Prompt,
    PromptType,
    EscapeStrategy,
    TemplateNotFoundError,
    MissingVariableError,
    InvalidTemplateError,
    UnsafeValueError,
)

# =============================================================================
# RESPONSE PARSER
# =============================================================================
from app.services.ai.response_parser import (
    ParsedResponse,
    VulnerabilityFinding,
    AnalysisType,
    SeverityLevel,
    ConfidenceLevel,
)

# =============================================================================
# RE-EXPORT RESPONSE PARSER EXCEPTIONS (from exceptions module)
# =============================================================================
# These are already imported from exceptions module above

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Service Layer
    "AIService",
    # Client Layer
    "AIClient",
    "AIClientError",
    # Model Management
    "ModelManager",
    "ModelConfig",
    "ModelProvider",
    # Prompt Builder
    "PromptBuilder",
    "PromptBuilderError",
    "PromptTemplate",
    "Prompt",
    "PromptType",
    "EscapeStrategy",
    "TemplateNotFoundError",
    "MissingVariableError",
    "InvalidTemplateError",
    "UnsafeValueError",
    # Response Parser
    "ResponseParserError",
    "ParsedResponse",
    "VulnerabilityFinding",
    "AnalysisType",
    "SeverityLevel",
    "ConfidenceLevel",
    "InvalidJSONError",
    "EmptyResponseError",
    "MalformedResponseError",
    "MissingFieldError",
    "InvalidFieldTypeError",
    # Exceptions - Base
    "AIServiceError",
    "ModelNotConfiguredError",
    "PromptBuildError",
    "GenerationError",
    "ParseError",
    # Exceptions - Configuration
    "AIConfigurationError",
    "AIModelError",
    "AIModelNotFoundError",
    "AIModelDisabledError",
    # Exceptions - Connection
    "AIConnectionError",
    "AIRequestTimeoutError",
    # Exceptions - Authentication
    "AIAuthenticationError",
    # Exceptions - Request
    "AIRequestError",
    "AIRateLimitError",
    # Exceptions - Response
    "AIResponseError",
    "AIProviderError",
    # Exceptions - Parsing
    "AIParsingError",
    # Exceptions - Prompt
    "PromptTemplateError",
    "PromptValidationError",
]
