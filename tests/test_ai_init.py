# =============================================================================
# FILE: tests/test_ai_init.py
# =============================================================================
# DESCRIPTION: Unit tests for AI service package initialization
# =============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the package
# Note: ResponseParser is not exported from the package,
# but it exists in the response_parser module
import app.services.ai as ai_package
from app.services.ai import (
    AIAuthenticationError,
    # Client Layer
    AIClient,
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
    # Service Layer
    AIService,
    AIServiceError,
    AnalysisType,
    ConfidenceLevel,
    EscapeStrategy,
    GenerationError,
    ModelConfig,
    ModelManager,
    ModelNotConfiguredError,
    ModelProvider,
    ParsedResponse,
    ParseError,
    Prompt,
    # Prompt Builder
    PromptBuilder,
    PromptBuilderError,
    PromptBuildError,
    PromptTemplate,
    PromptTemplateError,
    PromptType,
    PromptValidationError,
    ResponseParserError,
    SeverityLevel,
    VulnerabilityFinding,
)

# =============================================================================
# TEST: PACKAGE IMPORTS
# =============================================================================


class TestPackageImports:
    """Tests for package imports."""

    def test_package_imports_without_error(self) -> None:
        """Test that the package imports without error."""
        assert ai_package is not None

    def test_all_contains_expected_names(self) -> None:
        """Test that __all__ contains all expected names."""
        expected_names = {
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
            "EmptyResponseError",
            "InvalidJSONError",
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
        }

        all_set = set(ai_package.__all__)
        assert all_set == expected_names, (
            f"Missing: {expected_names - all_set}, Extra: {all_set - expected_names}"
        )

    def test_no_duplicate_exports(self) -> None:
        """Test that there are no duplicate exports in __all__."""
        all_list = ai_package.__all__
        all_set = set(all_list)
        assert len(all_list) == len(all_set), "Duplicate entries found in __all__"

    def test_all_exports_exist(self) -> None:
        """Test that every name in __all__ exists in the module."""
        for name in ai_package.__all__:
            assert hasattr(ai_package, name), f"'{name}' exported but not defined"


# =============================================================================
# TEST: IMPORTED OBJECTS
# =============================================================================


class TestImportedObjects:
    """Tests for imported objects."""

    def test_ai_service_class(self) -> None:
        """Test that AIService is imported correctly."""
        assert AIService is not None
        assert callable(AIService)

    def test_ai_client_class(self) -> None:
        """Test that AIClient is imported correctly."""
        assert AIClient is not None
        assert callable(AIClient)

    def test_model_manager_class(self) -> None:
        """Test that ModelManager is imported correctly."""
        assert ModelManager is not None
        assert callable(ModelManager)

    def test_prompt_builder_class(self) -> None:
        """Test that PromptBuilder is imported correctly."""
        assert PromptBuilder is not None
        assert callable(PromptBuilder)

    def test_model_config_class(self) -> None:
        """Test that ModelConfig is imported correctly."""
        assert ModelConfig is not None
        assert callable(ModelConfig)

    def test_prompt_class(self) -> None:
        """Test that Prompt is imported correctly."""
        assert Prompt is not None
        assert callable(Prompt)

    def test_prompt_template_class(self) -> None:
        """Test that PromptTemplate is imported correctly."""
        assert PromptTemplate is not None
        assert callable(PromptTemplate)

    def test_parsed_response_class(self) -> None:
        """Test that ParsedResponse is imported correctly."""
        assert ParsedResponse is not None
        assert callable(ParsedResponse)

    def test_vulnerability_finding_class(self) -> None:
        """Test that VulnerabilityFinding is imported correctly."""
        assert VulnerabilityFinding is not None
        assert callable(VulnerabilityFinding)


# =============================================================================
# TEST: ENUMS
# =============================================================================


class TestEnums:
    """Tests for enum imports."""

    def test_model_provider_enum(self) -> None:
        """Test that ModelProvider enum is imported correctly."""
        assert ModelProvider is not None
        assert hasattr(ModelProvider, "OLLAMA")
        assert hasattr(ModelProvider, "OPENAI")
        assert hasattr(ModelProvider, "CLAUDE")
        assert hasattr(ModelProvider, "GEMINI")

    def test_prompt_type_enum(self) -> None:
        """Test that PromptType enum is imported correctly."""
        assert PromptType is not None
        assert hasattr(PromptType, "SQL_INJECTION_ANALYSIS")
        assert hasattr(PromptType, "XSS_ANALYSIS")
        assert hasattr(PromptType, "CUSTOM")

    def test_escape_strategy_enum(self) -> None:
        """Test that EscapeStrategy enum is imported correctly."""
        assert EscapeStrategy is not None
        assert hasattr(EscapeStrategy, "HTML")
        assert hasattr(EscapeStrategy, "SQL")
        assert hasattr(EscapeStrategy, "JSON")

    def test_analysis_type_enum(self) -> None:
        """Test that AnalysisType enum is imported correctly."""
        assert AnalysisType is not None
        assert hasattr(AnalysisType, "SQL_INJECTION")
        assert hasattr(AnalysisType, "XSS")
        assert hasattr(AnalysisType, "GENERIC")

    def test_severity_level_enum(self) -> None:
        """Test that SeverityLevel enum is imported correctly."""
        assert SeverityLevel is not None
        assert hasattr(SeverityLevel, "CRITICAL")
        assert hasattr(SeverityLevel, "HIGH")
        assert hasattr(SeverityLevel, "MEDIUM")
        assert hasattr(SeverityLevel, "LOW")

    def test_confidence_level_enum(self) -> None:
        """Test that ConfidenceLevel enum is imported correctly."""
        assert ConfidenceLevel is not None
        assert hasattr(ConfidenceLevel, "HIGH")
        assert hasattr(ConfidenceLevel, "MEDIUM")
        assert hasattr(ConfidenceLevel, "LOW")
        assert hasattr(ConfidenceLevel, "UNKNOWN")


# =============================================================================
# TEST: EXCEPTIONS
# =============================================================================


class TestExceptions:
    """Tests for exception imports."""

    def test_base_exception(self) -> None:
        """Test that AIServiceError is imported correctly."""
        assert AIServiceError is not None
        assert issubclass(AIServiceError, Exception)

    def test_configuration_exceptions(self) -> None:
        """Test that configuration exceptions are imported correctly."""
        assert AIConfigurationError is not None
        assert issubclass(AIConfigurationError, AIServiceError)

    def test_connection_exceptions(self) -> None:
        """Test that connection exceptions are imported correctly."""
        assert AIConnectionError is not None
        assert issubclass(AIConnectionError, AIServiceError)
        assert AIRequestTimeoutError is not None
        assert issubclass(AIRequestTimeoutError, AIConnectionError)

    def test_authentication_exceptions(self) -> None:
        """Test that authentication exceptions are imported correctly."""
        assert AIAuthenticationError is not None
        assert issubclass(AIAuthenticationError, AIServiceError)

    def test_model_exceptions(self) -> None:
        """Test that model exceptions are imported correctly."""
        assert AIModelError is not None
        assert issubclass(AIModelError, AIServiceError)
        assert AIModelNotFoundError is not None
        assert issubclass(AIModelNotFoundError, AIModelError)
        assert AIModelDisabledError is not None
        assert issubclass(AIModelDisabledError, AIModelError)

    def test_request_exceptions(self) -> None:
        """Test that request exceptions are imported correctly."""
        assert AIRequestError is not None
        assert issubclass(AIRequestError, AIServiceError)
        assert AIRateLimitError is not None
        assert issubclass(AIRateLimitError, AIRequestError)

    def test_response_exceptions(self) -> None:
        """Test that response exceptions are imported correctly."""
        assert AIResponseError is not None
        assert issubclass(AIResponseError, AIServiceError)
        assert AIProviderError is not None
        assert issubclass(AIProviderError, AIServiceError)

    def test_parsing_exceptions(self) -> None:
        """Test that parsing exceptions are imported correctly."""
        assert AIParsingError is not None
        assert issubclass(AIParsingError, AIServiceError)
        assert ResponseParserError is not None
        assert issubclass(ResponseParserError, AIParsingError)

    def test_prompt_exceptions(self) -> None:
        """Test that prompt exceptions are imported correctly."""
        assert PromptBuilderError is not None
        assert issubclass(PromptBuilderError, AIServiceError)
        assert PromptTemplateError is not None
        assert issubclass(PromptTemplateError, PromptBuilderError)
        assert PromptValidationError is not None
        assert issubclass(PromptValidationError, PromptBuilderError)

    def test_service_layer_exceptions(self) -> None:
        """Test that service layer exceptions are imported correctly."""
        assert ModelNotConfiguredError is not None
        assert issubclass(ModelNotConfiguredError, AIServiceError)
        assert PromptBuildError is not None
        assert issubclass(PromptBuildError, AIServiceError)
        assert GenerationError is not None
        assert issubclass(GenerationError, AIServiceError)
        assert ParseError is not None
        assert issubclass(ParseError, AIServiceError)


# =============================================================================
# TEST: WILDCARD IMPORTS
# =============================================================================


class TestWildcardImports:
    """Tests for wildcard imports."""

    def test_wildcard_import_exposes_only_public_api(self) -> None:
        """Test that wildcard import only exposes public API."""
        public_names = set(ai_package.__all__)
        all_defined = set(dir(ai_package))
        public_defined = {name for name in all_defined if not name.startswith("_")}
        assert public_names.issubset(public_defined), (
            "Some names in __all__ are not defined"
        )


# =============================================================================
# TEST: OBJECT TYPE VERIFICATION
# =============================================================================


class TestObjectTypeVerification:
    """Tests for verifying imported objects are of correct type."""

    def test_ai_service_is_class(self) -> None:
        """Test that AIService is a class."""
        assert isinstance(AIService, type)

    def test_model_config_is_class(self) -> None:
        """Test that ModelConfig is a class."""
        assert isinstance(ModelConfig, type)

    def test_model_provider_is_enum(self) -> None:
        """Test that ModelProvider is an enum."""
        assert isinstance(ModelProvider, type)
        assert hasattr(ModelProvider, "__members__")

    def test_analysis_type_is_enum(self) -> None:
        """Test that AnalysisType is an enum."""
        assert isinstance(AnalysisType, type)
        assert hasattr(AnalysisType, "__members__")

    def test_severity_level_is_enum(self) -> None:
        """Test that SeverityLevel is an enum."""
        assert isinstance(SeverityLevel, type)
        assert hasattr(SeverityLevel, "__members__")

    def test_confidence_level_is_enum(self) -> None:
        """Test that ConfidenceLevel is an enum."""
        assert isinstance(ConfidenceLevel, type)
        assert hasattr(ConfidenceLevel, "__members__")


# =============================================================================
# TEST: CIRCULAR IMPORT CHECK
# =============================================================================


class TestCircularImports:
    """Tests for circular imports."""

    def test_no_circular_imports(self) -> None:
        """Test that there are no circular imports."""
        import app.services.ai as ai_pkg

        assert ai_pkg is not None
