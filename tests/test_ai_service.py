# =============================================================================
# FILE: tests/test_ai_service.py
# =============================================================================
# DESCRIPTION: Unit tests for AIService - Complete Fixed Version
# =============================================================================

import pytest
import threading
from unittest.mock import Mock, patch, MagicMock, call
from typing import List, Dict, Any

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.ai.ai_service import (
    AIService,
    AIServiceError,
    ModelNotConfiguredError,
    PromptBuildError,
    GenerationError,
    ParseError,
)
from app.services.ai.prompt_builder import (
    PromptBuilder,
    PromptTemplate,
    PromptType,
    Prompt,
    PromptBuilderError,
)
from app.services.ai.response_parser import (
    ResponseParser,
    ParsedResponse,
    AnalysisType,
    SeverityLevel,
    ConfidenceLevel,
    VulnerabilityFinding,
    ResponseParserError,
    EmptyResponseError,
    InvalidJSONError,
)
from app.services.ai.model_manager import ModelManager, ModelConfig, ModelProvider
from app.services.ai.ai_client import AIClient, AIClientError

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_model_manager() -> Mock:
    """Create a mock ModelManager."""
    manager = Mock(spec=ModelManager)
    model_config = ModelConfig(
        model_id="test-model",
        provider=ModelProvider.OLLAMA,
        api_key="test-key",
        base_url="http://localhost:11434",
    )
    manager.get_active_model.return_value = model_config
    manager.get_all_models.return_value = [model_config]
    return manager


@pytest.fixture
def mock_prompt_builder() -> Mock:
    """Create a mock PromptBuilder."""
    builder = Mock(spec=PromptBuilder)
    prompt = Prompt(
        system_prompt="System prompt",
        user_prompt="User prompt",
        template_name="test_template",
        variables={},
        prompt_type=PromptType.CUSTOM,
    )
    builder.build_prompt.return_value = prompt
    return builder


@pytest.fixture
def mock_response_parser() -> Mock:
    """Create a mock ResponseParser."""
    parser = Mock(spec=ResponseParser)
    parsed_response = ParsedResponse(
        analysis_type=AnalysisType.SQL_INJECTION,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        summary="Test summary",
        confidence=ConfidenceLevel.HIGH,
    )
    parser.parse_sql_analysis.return_value = parsed_response
    parser.parse_xss_analysis.return_value = parsed_response
    parser.parse_reverse_engineering.return_value = parsed_response
    parser.parse_malware_analysis.return_value = parsed_response
    parser.parse_vulnerability_explanation.return_value = parsed_response
    parser.parse_security_report.return_value = parsed_response
    return parser


@pytest.fixture
def mock_ai_client() -> Mock:
    """Create a mock AIClient."""
    client = Mock(spec=AIClient)
    client.generate.return_value = "Generated response"
    return client


@pytest.fixture
def ai_service(
    mock_model_manager: Mock,
    mock_prompt_builder: Mock,
    mock_response_parser: Mock,
) -> AIService:
    """Create an AIService instance with mocks."""
    return AIService(
        model_manager=mock_model_manager,
        prompt_builder=mock_prompt_builder,
        response_parser=mock_response_parser,
    )


@pytest.fixture
def sample_parsed_response() -> ParsedResponse:
    """Create a sample parsed response."""
    finding = VulnerabilityFinding(
        title="SQL Injection",
        description="SQL injection vulnerability found",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        affected_component="Login Form",
        remediation="Use parameterized queries",
        cve_id="CVE-2024-1234",
        references=["https://example.com"],
    )
    return ParsedResponse(
        analysis_type=AnalysisType.SQL_INJECTION,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[finding],
        summary="Found 1 vulnerability",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )


# =============================================================================
# TEST: AISERVICE INITIALIZATION
# =============================================================================


class TestAIServiceInitialization:
    """Tests for AIService initialization."""

    def test_initialization(
        self,
        mock_model_manager: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test AIService initialization."""
        service = AIService(
            model_manager=mock_model_manager,
            prompt_builder=mock_prompt_builder,
            response_parser=mock_response_parser,
        )
        assert service._model_manager == mock_model_manager
        assert service._prompt_builder == mock_prompt_builder
        assert service._response_parser == mock_response_parser
        assert service._client is None
        assert service._active_model is None


# =============================================================================
# TEST: CLIENT MANAGEMENT
# =============================================================================


class TestClientManagement:
    """Tests for client management."""

    def test_get_client_creates_client(
        self,
        ai_service: AIService,
    ) -> None:
        """Test that _get_client creates a client."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            mock_client_instance = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client_instance

            client = ai_service._get_client()

            assert client is not None
            assert client == mock_client_instance
            assert ai_service._client is not None
            assert ai_service._active_model is not None
            mock_client_class.assert_called_once()

    def test_get_client_uses_cache(
        self,
        ai_service: AIService,
    ) -> None:
        """Test that _get_client uses cached client."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            mock_client_instance = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client_instance

            client1 = ai_service._get_client()
            client2 = ai_service._get_client()

            assert client1 is client2
            mock_client_class.assert_called_once()

    def test_get_client_no_model(
        self,
        mock_model_manager: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test that _get_client raises error when no model configured."""
        mock_model_manager.get_active_model.return_value = None
        service = AIService(
            model_manager=mock_model_manager,
            prompt_builder=mock_prompt_builder,
            response_parser=mock_response_parser,
        )
        with pytest.raises(ModelNotConfiguredError, match="No active model configured"):
            service._get_client()

    def test_set_active_model_clears_cache(
        self,
        ai_service: AIService,
    ) -> None:
        """Test that setting active model clears the cached client."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            # First client
            mock_client1 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client1

            client1 = ai_service._get_client()
            assert client1 is not None
            mock_client_class.assert_called_once()

            # Switch model
            new_model = ModelConfig(
                model_id="new-model",
                provider=ModelProvider.OPENAI,
                api_key="new-key",
                base_url="https://api.openai.com",
            )
            ai_service.set_active_model(new_model)

            assert ai_service._client is None
            assert ai_service._active_model is None

            # Second client should be different
            mock_client2 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client2

            client2 = ai_service._get_client()
            assert client2 is not None
            assert client2 is not client1
            assert mock_client_class.call_count == 2

    def test_clear_client_cache(
        self,
        ai_service: AIService,
    ) -> None:
        """Test clearing the client cache."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            # First client
            mock_client1 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client1

            client1 = ai_service._get_client()
            assert client1 is not None
            mock_client_class.assert_called_once()

            # Clear cache
            ai_service.clear_client_cache()
            assert ai_service._client is None
            assert ai_service._active_model is None

            # Second client should be different
            mock_client2 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client2

            client2 = ai_service._get_client()
            assert client2 is not None
            assert client2 is not client1
            assert mock_client_class.call_count == 2

    def test_get_client_status(
        self,
        ai_service: AIService,
    ) -> None:
        """Test getting client status."""
        status = ai_service.get_client_status()
        assert status["client_initialized"] is False
        assert status["active_model"] is None
        assert status["client_cached"] is False

        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            mock_client_instance = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client_instance

            ai_service._get_client()
            status = ai_service.get_client_status()
            assert status["client_initialized"] is True
            assert status["active_model"] is not None
            assert status["client_cached"] is True


# =============================================================================
# TEST: GENERATE METHOD
# =============================================================================


class TestGenerate:
    """Tests for generate method."""

    def test_generate_success(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
    ) -> None:
        """Test successful generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            response = ai_service.generate("Test prompt")
            assert response == "Generated response"
            mock_ai_client.generate.assert_called_once_with("Test prompt", None)

    def test_generate_with_system_prompt(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
    ) -> None:
        """Test generation with system prompt."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            response = ai_service.generate("Test prompt", system_prompt="System prompt")
            assert response == "Generated response"
            mock_ai_client.generate.assert_called_once_with(
                "Test prompt", "System prompt"
            )

    def test_generate_no_model(
        self,
        mock_model_manager: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test generation when no model configured."""
        mock_model_manager.get_active_model.return_value = None
        service = AIService(
            model_manager=mock_model_manager,
            prompt_builder=mock_prompt_builder,
            response_parser=mock_response_parser,
        )
        with pytest.raises(GenerationError, match="No active model configured"):
            service.generate("Test prompt")

    def test_generate_client_error(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
    ) -> None:
        """Test generation when client raises error."""
        mock_ai_client.generate.side_effect = AIClientError("Client error")
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            with pytest.raises(
                GenerationError, match="Failed to generate response: Client error"
            ):
                ai_service.generate("Test prompt")


# =============================================================================
# TEST: HELPER GENERATION METHODS
# =============================================================================


class TestHelperGeneration:
    """Tests for helper generation methods."""

    def test_generate_sql_analysis(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test SQL analysis generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_sql_analysis(
                sql_query="SELECT * FROM users",
                context="Test context",
                additional_analysis="Test analysis",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_sql_analysis.assert_called_once()

    def test_generate_xss_analysis(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test XSS analysis generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_xss_analysis(
                code="<script>alert('xss')</script>",
                context="Test context",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_xss_analysis.assert_called_once()

    def test_generate_reverse_engineering(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test reverse engineering analysis generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_reverse_engineering(
                binary_info="Binary: test.exe",
                context="Test context",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_reverse_engineering.assert_called_once()

    def test_generate_malware_analysis(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test malware analysis generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_malware_analysis(
                malware_info="Malware: Trojan",
                context="Test context",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_malware_analysis.assert_called_once()

    def test_generate_vulnerability_explanation(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test vulnerability explanation generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_vulnerability_explanation(
                vulnerability="SQL Injection",
                context="Test context",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_vulnerability_explanation.assert_called_once()

    def test_generate_security_report(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test security report generation."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_security_report(
                report_data="Report: Security scan",
                context="Test context",
            )
            assert result is not None
            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_security_report.assert_called_once()


# =============================================================================
# TEST: ERROR HANDLING
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_prompt_build_error(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
    ) -> None:
        """Test prompt build error handling."""
        mock_prompt_builder.build_prompt.side_effect = PromptBuilderError("Build error")
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            with pytest.raises(
                PromptBuildError, match="Failed to build prompt: Build error"
            ):
                ai_service.generate_sql_analysis("SELECT 1")

    def test_generation_error(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
    ) -> None:
        """Test generation error handling."""
        mock_ai_client.generate.side_effect = AIClientError("Generation error")
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            with pytest.raises(
                GenerationError, match="Failed to generate response: Generation error"
            ):
                ai_service.generate_sql_analysis("SELECT 1")

    def test_parse_error(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test parse error handling."""
        mock_response_parser.parse_sql_analysis.side_effect = ResponseParserError(
            "Parse error"
        )
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            with pytest.raises(
                ParseError, match="Failed to parse response: Parse error"
            ):
                ai_service.generate_sql_analysis("SELECT 1")

    def test_model_not_configured_error(
        self,
        mock_model_manager: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
    ) -> None:
        """Test model not configured error."""
        mock_model_manager.get_active_model.return_value = None
        service = AIService(
            model_manager=mock_model_manager,
            prompt_builder=mock_prompt_builder,
            response_parser=mock_response_parser,
        )
        with pytest.raises(GenerationError, match="No active model configured"):
            service.generate_sql_analysis("SELECT 1")


# =============================================================================
# TEST: MODEL MANAGEMENT
# =============================================================================


class TestModelManagement:
    """Tests for model management."""

    def test_get_active_model(
        self,
        ai_service: AIService,
        mock_model_manager: Mock,
    ) -> None:
        """Test getting active model."""
        model = ai_service.get_active_model()
        assert model is not None
        mock_model_manager.get_active_model.assert_called_once()

    def test_set_active_model(
        self,
        ai_service: AIService,
        mock_model_manager: Mock,
    ) -> None:
        """Test setting active model."""
        new_model = ModelConfig(
            model_id="new-model",
            provider=ModelProvider.OPENAI,
            api_key="new-key",
            base_url="https://api.openai.com",
        )
        ai_service.set_active_model(new_model)
        mock_model_manager.set_active_model_config.assert_called_once_with(new_model)

    def test_get_available_models(
        self,
        ai_service: AIService,
        mock_model_manager: Mock,
    ) -> None:
        """Test getting available models."""
        models = ai_service.get_available_models()
        assert len(models) == 1
        mock_model_manager.get_all_models.assert_called_once()


# =============================================================================
# TEST: THREAD SAFETY
# =============================================================================


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_get_client(
        self,
        ai_service: AIService,
    ) -> None:
        """Test concurrent client access."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            mock_client = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client

            def get_client() -> None:
                client = ai_service._get_client()
                assert client is not None

            threads = []
            for _ in range(10):
                t = threading.Thread(target=get_client)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            assert ai_service._client is not None
            mock_client_class.assert_called_once()

    def test_concurrent_generate(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
    ) -> None:
        """Test concurrent generate calls."""
        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):

            def generate() -> None:
                response = ai_service.generate("Test prompt")
                assert response == "Generated response"

            threads = []
            for _ in range(10):
                t = threading.Thread(target=generate)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            assert mock_ai_client.generate.call_count == 10

    def test_concurrent_model_switch(
        self,
        ai_service: AIService,
    ) -> None:
        """Test concurrent model switching."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            mock_client_class.return_value = Mock(spec=AIClient)

            def switch_model(index: int) -> None:
                model = ModelConfig(
                    model_id=f"model-{index}",
                    provider=ModelProvider.OLLAMA,
                    api_key="test-key",
                    base_url="http://localhost:11434",
                )
                ai_service.set_active_model(model)

            threads = []
            for i in range(5):
                t = threading.Thread(target=switch_model, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()


# =============================================================================
# TEST: INTEGRATION
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_full_workflow(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
        mock_response_parser: Mock,
        sample_parsed_response: ParsedResponse,
    ) -> None:
        """Test full workflow from prompt to parsed response."""
        mock_response_parser.parse_sql_analysis.return_value = sample_parsed_response

        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            result = ai_service.generate_sql_analysis(
                sql_query="SELECT * FROM users WHERE id = 1",
                context="User login form",
                additional_analysis="Test analysis",
            )

            assert result is not None
            assert result.analysis_type == AnalysisType.SQL_INJECTION
            assert len(result.findings) == 1
            assert result.findings[0].title == "SQL Injection"
            assert result.findings[0].severity == SeverityLevel.HIGH
            assert result.confidence == ConfidenceLevel.HIGH

            mock_prompt_builder.build_prompt.assert_called_once()
            mock_ai_client.generate.assert_called_once()
            mock_response_parser.parse_sql_analysis.assert_called_once()

    def test_model_switch_workflow(
        self,
        ai_service: AIService,
    ) -> None:
        """Test workflow with model switching."""
        with patch("app.services.ai.ai_service.AIClient") as mock_client_class:
            # First client
            mock_client1 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client1

            ai_service.generate("First prompt")
            assert ai_service._client is not None
            first_client = ai_service._client
            mock_client_class.assert_called_once()

            # Switch model
            new_model = ModelConfig(
                model_id="new-model",
                provider=ModelProvider.OPENAI,
                api_key="new-key",
                base_url="https://api.openai.com",
            )
            ai_service.set_active_model(new_model)

            # Second client should be different
            mock_client2 = Mock(spec=AIClient)
            mock_client_class.return_value = mock_client2

            ai_service.generate("Second prompt")
            assert ai_service._client is not None
            assert ai_service._client is not first_client
            assert mock_client_class.call_count == 2

    def test_error_recovery(
        self,
        ai_service: AIService,
        mock_ai_client: Mock,
        mock_prompt_builder: Mock,
    ) -> None:
        """Test error recovery after failure."""
        mock_prompt_builder.build_prompt.side_effect = PromptBuilderError("Build error")

        with patch("app.services.ai.ai_service.AIClient", return_value=mock_ai_client):
            with pytest.raises(PromptBuildError):
                ai_service.generate_sql_analysis("SELECT 1")

            mock_prompt_builder.build_prompt.side_effect = None

            result = ai_service.generate_sql_analysis("SELECT 1")
            assert result is not None
