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
# =============================================================================
# CLIENT LAYER
# =============================================================================
from app.services.ai.ai_client import (
    AIClient,
    AIClientError,
)

# =============================================================================
# SERVICE LAYER
# =============================================================================
from app.services.ai.ai_service import (
    AIService,
)
from app.services.ai.exceptions import (
    AIAuthenticationError,
    AIConfigurationError,
    AIConnectionError,
    AIModelDisabledError,
    AIModelError,
    AIModelNotFoundError,
    AIParsingError,
    AIProviderError,
    AIRateLimitError,
    AIRequestError,
    AIRequestTimeoutError,
    AIResponseError,
    AIServiceError,
    EmptyResponseError,
    GenerationError,
    InvalidFieldTypeError,
    InvalidJSONError,
    MalformedResponseError,
    MissingFieldError,
    ModelNotConfiguredError,
    ParseError,
    PromptBuilderError,
    PromptBuildError,
    PromptTemplateError,
    PromptValidationError,
    ResponseParserError,
)

# =============================================================================
# MODEL MANAGEMENT
# =============================================================================
from app.services.ai.model_manager import (
    ModelConfig,
    ModelManager,
    ModelProvider,
)

# =============================================================================
# PROMPT BUILDER
# =============================================================================
from app.services.ai.prompt_builder import (
    EscapeStrategy,
    InvalidTemplateError,
    MissingVariableError,
    Prompt,
    PromptBuilder,
    PromptTemplate,
    PromptType,
    TemplateNotFoundError,
    UnsafeValueError,
)

# =============================================================================
# RESPONSE PARSER
# =============================================================================
from app.services.ai.response_parser import (
    AnalysisType,
    ConfidenceLevel,
    ParsedResponse,
    SeverityLevel,
    VulnerabilityFinding,
)

# =============================================================================
# RE-EXPORT RESPONSE PARSER EXCEPTIONS (from exceptions module)
# =============================================================================
# These are already imported from exceptions module above

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Exceptions - Authentication
    "AIAuthenticationError",
    # Client Layer
    "AIClient",
    "AIClientError",
    # Exceptions - Configuration
    "AIConfigurationError",
    # Exceptions - Connection
    "AIConnectionError",
    "AIModelDisabledError",
    "AIModelError",
    "AIModelNotFoundError",
    # Exceptions - Parsing
    "AIParsingError",
    "AIProviderError",
    "AIRateLimitError",
    # Exceptions - Request
    "AIRequestError",
    "AIRequestTimeoutError",
    # Exceptions - Response
    "AIResponseError",
    # Service Layer
    "AIService",
    # Exceptions - Base
    "AIServiceError",
    "AnalysisType",
    "ConfidenceLevel",
    "EmptyResponseError",
    "EscapeStrategy",
    "GenerationError",
    "InvalidFieldTypeError",
    "InvalidJSONError",
    "InvalidTemplateError",
    "MalformedResponseError",
    "MissingFieldError",
    "MissingVariableError",
    "ModelConfig",
    # Model Management
    "ModelManager",
    "ModelNotConfiguredError",
    "ModelProvider",
    "ParseError",
    "ParsedResponse",
    "Prompt",
    "PromptBuildError",
    # Prompt Builder
    "PromptBuilder",
    "PromptBuilderError",
    "PromptTemplate",
    # Exceptions - Prompt
    "PromptTemplateError",
    "PromptType",
    "PromptValidationError",
    # Response Parser
    "ResponseParserError",
    "SeverityLevel",
    "TemplateNotFoundError",
    "UnsafeValueError",
    "VulnerabilityFinding",
]
