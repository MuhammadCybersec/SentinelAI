# =============================================================================
# FILE: app/services/ai/ai_service.py
# =============================================================================
# DESCRIPTION:
# Main orchestration layer for AI services in SentinelAI.
# This class coordinates PromptBuilder, ModelManager, AIClient, and ResponseParser.
# =============================================================================

import threading
from typing import Optional, Dict, Any, List, Union

from app.services.ai.prompt_builder import (
    PromptBuilder,
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
    MalformedResponseError,
    MissingFieldError,
    InvalidFieldTypeError,
)
from app.services.ai.model_manager import ModelManager, ModelConfig, ModelProvider
from app.services.ai.ai_client import AIClient, AIClientError

# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class AIServiceError(Exception):
    """Base exception for AI service errors."""

    pass


class ModelNotConfiguredError(AIServiceError):
    """Raised when no model is configured."""

    pass


class PromptBuildError(AIServiceError):
    """Raised when prompt building fails."""

    pass


class GenerationError(AIServiceError):
    """Raised when AI generation fails."""

    pass


class ParseError(AIServiceError):
    """Raised when response parsing fails."""

    pass


# =============================================================================
# AI SERVICE CLASS
# =============================================================================


class AIService:
    """
    Main orchestration layer for AI services.

    This class coordinates:
        - PromptBuilder: Builds prompts
        - ModelManager: Manages model configuration
        - AIClient: Communicates with AI providers
        - ResponseParser: Parses AI responses

    Features:
        - Lazy client initialization
        - Client caching with model switching
        - Thread-safe operations
        - Comprehensive error handling
        - Provider-agnostic
    """

    # Template names for built-in analyses
    _TEMPLATE_SQL = "sql_injection_analysis"
    _TEMPLATE_XSS = "xss_analysis"
    _TEMPLATE_REVERSE = "reverse_engineering"
    _TEMPLATE_MALWARE = "malware_analysis"
    _TEMPLATE_VULNERABILITY = "vulnerability_explanation"
    _TEMPLATE_SECURITY = "security_report"

    def __init__(
        self,
        model_manager: ModelManager,
        prompt_builder: PromptBuilder,
        response_parser: ResponseParser,
    ) -> None:
        """
        Initialize the AI Service.

        Args:
            model_manager: ModelManager instance for model configuration
            prompt_builder: PromptBuilder instance for building prompts
            response_parser: ResponseParser instance for parsing responses
        """
        self._model_manager = model_manager
        self._prompt_builder = prompt_builder
        self._response_parser = response_parser

        self._client: Optional[AIClient] = None
        self._active_model: Optional[ModelConfig] = None
        self._lock = threading.RLock()

    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================

    def _get_client(self) -> AIClient:
        """
        Get or create the AI client.

        This method lazily initializes the client and caches it.
        If the active model changes, the client is recreated.

        Returns:
            AIClient: The AI client instance

        Raises:
            ModelNotConfiguredError: If no model is configured
        """
        with self._lock:
            current_model = self._model_manager.get_active_model()

            if current_model is None:
                raise ModelNotConfiguredError(
                    "No active model configured. Please set a model first."
                )

            # Check if we need to recreate the client
            if (
                self._client is None
                or self._active_model is None
                or self._active_model != current_model
            ):
                self._active_model = current_model
                self._client = AIClient(current_model)

            return self._client

    def _build_and_generate(
        self,
        template_name: str,
        variables: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Build a prompt and generate a response.

        Args:
            template_name: Name of the template to use
            variables: Variables for the template
            system_prompt: Optional system prompt override

        Returns:
            str: Generated response text

        Raises:
            PromptBuildError: If prompt building fails
            GenerationError: If generation fails
        """
        try:
            prompt = self._prompt_builder.build_prompt(
                template_name=template_name,
                variables=variables,
            )
        except PromptBuilderError as e:
            raise PromptBuildError(f"Failed to build prompt: {str(e)}") from e

        try:
            client = self._get_client()
            full_prompt = prompt.get_full_prompt()
            response = client.generate(full_prompt, system_prompt)
            return response
        except AIClientError as e:
            raise GenerationError(f"Failed to generate response: {str(e)}") from e
        except ModelNotConfiguredError as e:
            raise GenerationError(str(e)) from e

    def _build_generate_and_parse(
        self,
        template_name: str,
        variables: Dict[str, Any],
        parse_method: str,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Build, generate, and parse a response.

        Args:
            template_name: Name of the template to use
            variables: Variables for the template
            parse_method: Name of the parser method to call
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed response

        Raises:
            PromptBuildError: If prompt building fails
            GenerationError: If generation fails
            ParseError: If parsing fails
        """
        try:
            response_text = self._build_and_generate(
                template_name=template_name,
                variables=variables,
                system_prompt=system_prompt,
            )
        except (PromptBuildError, GenerationError) as e:
            raise

        try:
            parser_method = getattr(self._response_parser, parse_method)
            return parser_method(response_text)
        except (ResponseParserError, AttributeError) as e:
            raise ParseError(f"Failed to parse response: {str(e)}") from e

    # =========================================================================
    # PUBLIC METHODS
    # =========================================================================

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate a response from the AI model.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt

        Returns:
            str: Generated response text

        Raises:
            ModelNotConfiguredError: If no model is configured
            GenerationError: If generation fails
        """
        try:
            client = self._get_client()
            return client.generate(prompt, system_prompt)
        except AIClientError as e:
            raise GenerationError(f"Failed to generate response: {str(e)}") from e
        except ModelNotConfiguredError as e:
            raise GenerationError(str(e)) from e

    def generate_sql_analysis(
        self,
        sql_query: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate SQL injection analysis.

        Args:
            sql_query: The SQL query to analyze
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed analysis response
        """
        variables = {
            "sql_query": sql_query,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_SQL,
            variables=variables,
            parse_method="parse_sql_analysis",
            system_prompt=system_prompt,
        )

    def generate_xss_analysis(
        self,
        code: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate XSS analysis.

        Args:
            code: The code to analyze
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed analysis response
        """
        variables = {
            "code": code,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_XSS,
            variables=variables,
            parse_method="parse_xss_analysis",
            system_prompt=system_prompt,
        )

    def generate_reverse_engineering(
        self,
        binary_info: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate reverse engineering analysis.

        Args:
            binary_info: Information about the binary
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed analysis response
        """
        variables = {
            "binary_info": binary_info,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_REVERSE,
            variables=variables,
            parse_method="parse_reverse_engineering",
            system_prompt=system_prompt,
        )

    def generate_malware_analysis(
        self,
        malware_info: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate malware analysis.

        Args:
            malware_info: Information about the malware
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed analysis response
        """
        variables = {
            "malware_info": malware_info,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_MALWARE,
            variables=variables,
            parse_method="parse_malware_analysis",
            system_prompt=system_prompt,
        )

    def generate_vulnerability_explanation(
        self,
        vulnerability: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate vulnerability explanation.

        Args:
            vulnerability: The vulnerability to explain
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed explanation response
        """
        variables = {
            "vulnerability": vulnerability,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_VULNERABILITY,
            variables=variables,
            parse_method="parse_vulnerability_explanation",
            system_prompt=system_prompt,
        )

    def generate_security_report(
        self,
        report_data: str,
        context: Optional[str] = None,
        additional_analysis: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ) -> ParsedResponse:
        """
        Generate security report.

        Args:
            report_data: The data for the report
            context: Additional context
            additional_analysis: Additional analysis to include
            system_prompt: Optional system prompt override

        Returns:
            ParsedResponse: Parsed report response
        """
        variables = {
            "report_data": report_data,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self._build_generate_and_parse(
            template_name=self._TEMPLATE_SECURITY,
            variables=variables,
            parse_method="parse_security_report",
            system_prompt=system_prompt,
        )

    def get_active_model(self) -> Optional[ModelConfig]:
        """
        Get the active model configuration.

        Returns:
            Optional[ModelConfig]: The active model config
        """
        return self._model_manager.get_active_model()

    def set_active_model(self, model_config: ModelConfig) -> None:
        """
        Set the active model configuration.

        This will clear the cached client if the model changes.

        Args:
            model_config: The model configuration to set
        """
        with self._lock:
            self._model_manager.set_active_model_config(model_config)
            # Clear cached client to force recreation
            self._client = None
            self._active_model = None

    def get_available_models(self) -> List[ModelConfig]:
        """
        Get all available models.

        Returns:
            List[ModelConfig]: List of available model configurations
        """
        return self._model_manager.get_all_models()

    def clear_client_cache(self) -> None:
        """
        Clear the cached AI client.

        This forces recreation of the client on the next request.
        """
        with self._lock:
            self._client = None
            self._active_model = None

    def get_client_status(self) -> Dict[str, Any]:
        """
        Get the status of the current client.

        Returns:
            Dict[str, Any]: Client status information
        """
        with self._lock:
            return {
                "client_initialized": self._client is not None,
                "active_model": (
                    self._active_model.model_id if self._active_model else None
                ),
                "active_model_provider": (
                    self._active_model.provider.value if self._active_model else None
                ),
                "client_cached": self._client is not None,
            }
