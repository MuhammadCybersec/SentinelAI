# =============================================================================
# FILE: tests/test_ai_exceptions.py
# =============================================================================
# DESCRIPTION: Unit tests for AI service exceptions
# =============================================================================

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    InvalidFieldTypeError,
    InvalidJSONError,
    MalformedResponseError,
    MissingFieldError,
    PromptBuilderError,
    PromptTemplateError,
    PromptValidationError,
    ResponseParserError,
)

# =============================================================================
# TEST: BASE EXCEPTION
# =============================================================================


class TestAIServiceError:
    """Tests for AIServiceError base exception."""

    def test_exception_creation(self) -> None:
        """Test creating exception with default values."""
        error = AIServiceError("Test error")
        assert error.message == "Test error"
        assert error.provider is None
        assert error.model is None
        assert error.details == {}

    def test_exception_with_provider_and_model(self) -> None:
        """Test creating exception with provider and model."""
        error = AIServiceError(
            "Test error",
            provider="ollama",
            model="llama3",
        )
        assert error.message == "Test error"
        assert error.provider == "ollama"
        assert error.model == "llama3"
        assert error.details == {}

    def test_exception_with_details(self) -> None:
        """Test creating exception with details."""
        details = {"key": "value", "code": 500}
        error = AIServiceError(
            "Test error",
            provider="openai",
            model="gpt-4",
            details=details,
        )
        assert error.message == "Test error"
        assert error.provider == "openai"
        assert error.model == "gpt-4"
        assert error.details == details

    def test_exception_str_default(self) -> None:
        """Test string representation with default values."""
        error = AIServiceError("Test error")
        assert str(error) == "Test error"

    def test_exception_str_with_provider(self) -> None:
        """Test string representation with provider."""
        error = AIServiceError("Test error", provider="ollama")
        assert "Test error" in str(error)
        assert "Provider: ollama" in str(error)

    def test_exception_str_with_model(self) -> None:
        """Test string representation with model."""
        error = AIServiceError("Test error", model="llama3")
        assert "Test error" in str(error)
        assert "Model: llama3" in str(error)

    def test_exception_str_with_details(self) -> None:
        """Test string representation with details."""
        details = {"key": "value", "code": 500}
        error = AIServiceError("Test error", details=details)
        assert "Test error" in str(error)
        assert "Details:" in str(error)
        assert "key" in str(error)
        assert "value" in str(error)

    def test_exception_str_full(self) -> None:
        """Test string representation with all fields."""
        error = AIServiceError(
            "Test error",
            provider="ollama",
            model="llama3",
            details={"key": "value"},
        )
        result = str(error)
        assert "Test error" in result
        assert "Provider: ollama" in result
        assert "Model: llama3" in result
        assert "Details:" in result

    def test_exception_to_dict(self) -> None:
        """Test converting exception to dictionary."""
        error = AIServiceError(
            "Test error",
            provider="ollama",
            model="llama3",
            details={"key": "value"},
        )
        result = error.to_dict()
        assert result["type"] == "AIServiceError"
        assert result["message"] == "Test error"
        assert result["provider"] == "ollama"
        assert result["model"] == "llama3"
        assert result["details"] == {"key": "value"}

    def test_exception_inheritance(self) -> None:
        """Test that AIServiceError inherits from Exception."""
        error = AIServiceError("Test error")
        assert isinstance(error, Exception)
        assert isinstance(error, AIServiceError)


# =============================================================================
# TEST: CONFIGURATION ERRORS
# =============================================================================


class TestConfigurationErrors:
    """Tests for configuration error exceptions."""

    def test_ai_configuration_error(self) -> None:
        """Test AIConfigurationError."""
        error = AIConfigurationError("Config error", provider="ollama")
        assert isinstance(error, AIServiceError)
        assert error.message == "Config error"
        assert error.provider == "ollama"

    def test_ai_model_not_found_error(self) -> None:
        """Test AIModelNotFoundError."""
        error = AIModelNotFoundError("Model not found", model="llama3")
        assert isinstance(error, AIModelError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Model not found"
        assert error.model == "llama3"

    def test_ai_model_disabled_error(self) -> None:
        """Test AIModelDisabledError."""
        error = AIModelDisabledError("Model disabled", model="llama3")
        assert isinstance(error, AIModelError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Model disabled"
        assert error.model == "llama3"

    def test_ai_model_error(self) -> None:
        """Test AIModelError."""
        error = AIModelError("Model error", provider="ollama", model="llama3")
        assert isinstance(error, AIServiceError)
        assert error.message == "Model error"
        assert error.provider == "ollama"
        assert error.model == "llama3"


# =============================================================================
# TEST: CONNECTION ERRORS
# =============================================================================


class TestConnectionErrors:
    """Tests for connection error exceptions."""

    def test_ai_connection_error(self) -> None:
        """Test AIConnectionError."""
        error = AIConnectionError("Connection error", provider="openai")
        assert isinstance(error, AIServiceError)
        assert error.message == "Connection error"
        assert error.provider == "openai"

    def test_ai_request_timeout_error(self) -> None:
        """Test AIRequestTimeoutError."""
        error = AIRequestTimeoutError("Timeout", provider="ollama")
        assert isinstance(error, AIConnectionError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Timeout"


# =============================================================================
# TEST: AUTHENTICATION ERRORS
# =============================================================================


class TestAuthenticationErrors:
    """Tests for authentication error exceptions."""

    def test_ai_authentication_error(self) -> None:
        """Test AIAuthenticationError."""
        error = AIAuthenticationError("Auth error", provider="openai")
        assert isinstance(error, AIServiceError)
        assert error.message == "Auth error"
        assert error.provider == "openai"


# =============================================================================
# TEST: REQUEST ERRORS
# =============================================================================


class TestRequestErrors:
    """Tests for request error exceptions."""

    def test_ai_request_error(self) -> None:
        """Test AIRequestError."""
        error = AIRequestError("Request error", provider="ollama")
        assert isinstance(error, AIServiceError)
        assert error.message == "Request error"
        assert error.provider == "ollama"

    def test_ai_rate_limit_error(self) -> None:
        """Test AIRateLimitError."""
        error = AIRateLimitError("Rate limit exceeded", provider="openai")
        assert isinstance(error, AIRequestError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Rate limit exceeded"


# =============================================================================
# TEST: RESPONSE ERRORS
# =============================================================================


class TestResponseErrors:
    """Tests for response error exceptions."""

    def test_ai_response_error(self) -> None:
        """Test AIResponseError."""
        error = AIResponseError("Response error", provider="ollama")
        assert isinstance(error, AIServiceError)
        assert error.message == "Response error"
        assert error.provider == "ollama"

    def test_ai_provider_error(self) -> None:
        """Test AIProviderError."""
        error = AIProviderError("Provider error", provider="openai")
        assert isinstance(error, AIServiceError)
        assert error.message == "Provider error"
        assert error.provider == "openai"


# =============================================================================
# TEST: PARSING ERRORS
# =============================================================================


class TestParsingErrors:
    """Tests for parsing error exceptions."""

    def test_ai_parsing_error(self) -> None:
        """Test AIParsingError."""
        error = AIParsingError("Parsing error", provider="ollama")
        assert isinstance(error, AIServiceError)
        assert error.message == "Parsing error"
        assert error.provider == "ollama"

    def test_response_parser_error(self) -> None:
        """Test ResponseParserError."""
        error = ResponseParserError("Parser error")
        assert isinstance(error, AIParsingError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Parser error"

    def test_invalid_json_error(self) -> None:
        """Test InvalidJSONError."""
        error = InvalidJSONError("Invalid JSON", details={"position": 10})
        assert isinstance(error, ResponseParserError)
        assert isinstance(error, AIParsingError)
        assert isinstance(error, AIServiceError)
        assert error.message == "Invalid JSON"
        assert error.details == {"position": 10}

    def test_empty_response_error(self) -> None:
        """Test EmptyResponseError."""
        error = EmptyResponseError("Empty response")
        assert isinstance(error, ResponseParserError)
        assert isinstance(error, AIParsingError)
        assert isinstance(error, AIServiceError)

    def test_malformed_response_error(self) -> None:
        """Test MalformedResponseError."""
        error = MalformedResponseError("Malformed response")
        assert isinstance(error, ResponseParserError)
        assert isinstance(error, AIParsingError)

    def test_missing_field_error(self) -> None:
        """Test MissingFieldError."""
        error = MissingFieldError("Missing field", details={"field": "id"})
        assert isinstance(error, ResponseParserError)
        assert isinstance(error, AIParsingError)
        assert error.details == {"field": "id"}

    def test_invalid_field_type_error(self) -> None:
        """Test InvalidFieldTypeError."""
        error = InvalidFieldTypeError(
            "Invalid type", details={"field": "id", "expected": "str"}
        )
        assert isinstance(error, ResponseParserError)
        assert isinstance(error, AIParsingError)
        assert error.details == {"field": "id", "expected": "str"}


# =============================================================================
# TEST: PROMPT ERRORS
# =============================================================================


class TestPromptErrors:
    """Tests for prompt error exceptions."""

    def test_prompt_builder_error(self) -> None:
        """Test PromptBuilderError."""
        error = PromptBuilderError("Build error")
        assert isinstance(error, AIServiceError)
        assert error.message == "Build error"

    def test_prompt_template_error(self) -> None:
        """Test PromptTemplateError."""
        error = PromptTemplateError("Template error", details={"template": "test"})
        assert isinstance(error, PromptBuilderError)
        assert isinstance(error, AIServiceError)
        assert error.details == {"template": "test"}

    def test_prompt_validation_error(self) -> None:
        """Test PromptValidationError."""
        error = PromptValidationError(
            "Validation error",
            details={"missing": ["name", "id"]},
        )
        assert isinstance(error, PromptBuilderError)
        assert isinstance(error, AIServiceError)
        assert error.details == {"missing": ["name", "id"]}


# =============================================================================
# TEST: EXCEPTION HIERARCHY
# =============================================================================


class TestExceptionHierarchy:
    """Tests for exception inheritance hierarchy."""

    def test_all_exceptions_inherit_base(self) -> None:
        """Test that all exceptions inherit from AIServiceError."""
        exceptions = [
            AIConfigurationError(""),
            AIConnectionError(""),
            AIResponseError(""),
            AIProviderError(""),
            AIModelError(""),
            AIModelNotFoundError(""),
            AIModelDisabledError(""),
            AIRequestError(""),
            AIRequestTimeoutError(""),
            AIRateLimitError(""),
            AIAuthenticationError(""),
            AIParsingError(""),
            PromptBuilderError(""),
            PromptTemplateError(""),
            PromptValidationError(""),
            ResponseParserError(""),
            InvalidJSONError(""),
            EmptyResponseError(""),
            MalformedResponseError(""),
            MissingFieldError(""),
            InvalidFieldTypeError(""),
        ]
        for error in exceptions:
            assert isinstance(error, AIServiceError)

    def test_specific_inheritance(self) -> None:
        """Test specific inheritance relationships."""
        assert issubclass(AIRequestTimeoutError, AIConnectionError)
        assert issubclass(AIRateLimitError, AIRequestError)
        assert issubclass(AIModelNotFoundError, AIModelError)
        assert issubclass(AIModelDisabledError, AIModelError)
        assert issubclass(InvalidJSONError, ResponseParserError)
        assert issubclass(PromptTemplateError, PromptBuilderError)

    def test_exception_to_dict_all_fields(self) -> None:
        """Test to_dict for all exception types."""
        error = AIServiceError(
            "Test error",
            provider="ollama",
            model="llama3",
            details={"key": "value"},
        )
        result = error.to_dict()
        assert result["type"] == "AIServiceError"
        assert result["message"] == "Test error"
        assert result["provider"] == "ollama"
        assert result["model"] == "llama3"
        assert result["details"] == {"key": "value"}


# =============================================================================
# TEST: SERIALIZATION
# =============================================================================


class TestSerialization:
    """Tests for exception serialization."""

    def test_error_to_json(self) -> None:
        """Test converting error to JSON."""
        error = AIServiceError(
            "Test error",
            provider="ollama",
            model="llama3",
            details={"key": "value"},
        )
        json_str = json.dumps(error.to_dict())
        result = json.loads(json_str)
        assert result["type"] == "AIServiceError"
        assert result["message"] == "Test error"
        assert result["provider"] == "ollama"
        assert result["model"] == "llama3"
        assert result["details"] == {"key": "value"}

    def test_complex_details(self) -> None:
        """Test with complex details."""
        details = {
            "errors": ["error1", "error2"],
            "metadata": {"timestamp": 1234567890},
            "nested": {"inner": {"value": 42}},
        }
        error = AIServiceError("Complex error", details=details)
        json_str = json.dumps(error.to_dict())
        result = json.loads(json_str)
        assert result["details"]["errors"] == ["error1", "error2"]
        assert result["details"]["metadata"]["timestamp"] == 1234567890


# =============================================================================
# TEST: EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Edge case tests for exceptions."""

    def test_empty_message(self) -> None:
        """Test exception with empty message."""
        error = AIServiceError("")
        assert error.message == ""
        assert str(error) == ""

    def test_none_details(self) -> None:
        """Test with None details."""
        error = AIServiceError("Test", details=None)
        assert error.details == {}

    def test_empty_string_provider(self) -> None:
        """Test with empty string provider."""
        error = AIServiceError("Test", provider="")
        assert error.provider == ""
        # When provider is an empty string, it should still show "Provider: "
        # since we check "is not None" instead of truthiness
        assert str(error) == "Test\nProvider: "

    def test_nested_exceptions(self) -> None:
        """Test catching nested exceptions."""
        try:
            try:
                raise InvalidJSONError("Invalid JSON")
            except InvalidJSONError as e:
                raise AIServiceError("Wrapper error", details={"original": str(e)})
        except AIServiceError as e:
            assert e.message == "Wrapper error"
            assert "Invalid JSON" in str(e.details.get("original", ""))

    def test_missing_field_to_dict(self) -> None:
        """Test MissingFieldError to_dict."""
        error = MissingFieldError("Missing field", details={"field": "id"})
        result = error.to_dict()
        assert result["type"] == "MissingFieldError"
        assert result["details"]["field"] == "id"
