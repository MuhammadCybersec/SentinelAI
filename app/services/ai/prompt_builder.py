# app/services/ai/prompt_builder.py - FIXED VERSION

"""
Prompt Builder Service for SentinelAI.

This module provides a production-ready prompt builder that constructs
prompts for various security analysis tasks without calling any AI model.
It supports template rendering, variable validation, and escaping.

Design Principles:
- SOLID: Single Responsibility (only builds prompts)
- Clean Architecture: Independent of AI providers
- Thread Safety: Immutable templates and stateless rendering
- Provider Independent: No external dependencies
"""

import html
import json
import re
import threading
import time
import xml.sax.saxutils as xml_utils
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
)

# =============================================================================
# Custom Exceptions
# =============================================================================


class PromptBuilderError(Exception):
    """Base exception for prompt builder errors."""


class TemplateNotFoundError(PromptBuilderError):
    """Raised when a template is not found."""


class MissingVariableError(PromptBuilderError):
    """Raised when a required variable is missing."""


class InvalidTemplateError(PromptBuilderError):
    """Raised when a template is invalid."""


class UnsafeValueError(PromptBuilderError):
    """Raised when a value contains unsafe content."""


# =============================================================================
# Enums and Constants
# =============================================================================


class PromptType(Enum):
    """Types of prompts that can be built."""

    SYSTEM = "system"
    USER = "user"
    SQL_INJECTION_ANALYSIS = "sql_injection_analysis"
    XSS_ANALYSIS = "xss_analysis"
    REVERSE_ENGINEERING = "reverse_engineering"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY_EXPLANATION = "vulnerability_explanation"
    SECURITY_REPORT = "security_report"
    CUSTOM = "custom"


class EscapeStrategy(Enum):
    """Escape strategies for template values."""

    HTML = "html"
    XML = "xml"
    JSON = "json"
    SQL = "sql"
    SHELL = "shell"
    NONE = "none"


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass(slots=True, frozen=True)
class PromptTemplate:
    """
    Immutable prompt template with metadata.

    Attributes:
        name: Unique identifier for the template
        prompt_type: Type of prompt this template represents
        system_prompt: System-level instructions (optional)
        user_prompt_template: User prompt template with variables
        description: Human-readable description
        required_variables: Set of required variable names
        optional_variables: Set of optional variable names
        escape_strategy: Default escape strategy for values
        version: Template version for compatibility
        tags: Set of tags for categorization
    """

    name: str
    prompt_type: PromptType
    user_prompt_template: str
    system_prompt: str | None = None
    description: str = ""
    required_variables: frozenset[str] = field(default_factory=frozenset)
    optional_variables: frozenset[str] = field(default_factory=frozenset)
    escape_strategy: EscapeStrategy = EscapeStrategy.NONE
    version: str = "1.0.0"
    tags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate template after initialization."""
        if not self.name:
            raise InvalidTemplateError("Template name cannot be empty")
        if not self.user_prompt_template:
            raise InvalidTemplateError("User prompt template cannot be empty")
        if self.system_prompt is not None and not self.system_prompt.strip():
            raise InvalidTemplateError("System prompt cannot be empty string")

    def get_all_variables(self) -> frozenset[str]:
        """Get all variables (required + optional)."""
        return self.required_variables | self.optional_variables


@dataclass(slots=True)
class Prompt:
    """
    Rendered prompt with metadata.

    Attributes:
        system_prompt: Rendered system prompt (may be None)
        user_prompt: Rendered user prompt
        template_name: Name of the template used
        variables: Variables used in rendering
        prompt_type: Type of prompt
        rendered_at: Timestamp of rendering (set by builder)
    """

    system_prompt: str | None
    user_prompt: str
    template_name: str
    variables: dict[str, Any]
    prompt_type: PromptType
    rendered_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "template_name": self.template_name,
            "variables": self.variables,
            "prompt_type": self.prompt_type.value,
            "rendered_at": self.rendered_at,
        }

    def get_full_prompt(self) -> str:
        """
        Get the complete prompt (system + user).

        Returns:
            Combined prompt string
        """
        if self.system_prompt:
            return f"{self.system_prompt}\n\n{self.user_prompt}"
        return self.user_prompt


# =============================================================================
# PromptBuilder Class
# =============================================================================


class PromptBuilder:
    """
    Thread-safe prompt builder for security analysis prompts.

    This class is responsible only for building prompts. It does not call
    any AI models or external services.

    Features:
        - Immutable template storage
        - Variable validation
        - Escape unsafe values
        - Thread-safe rendering
        - Provider independent

    Example:
        >>> builder = PromptBuilder()
        >>> template = PromptTemplate(
        ...     name="sql_analysis",
        ...     prompt_type=PromptType.SQL_INJECTION_ANALYSIS,
        ...     system_prompt="You are a security expert.",
        ...     user_prompt_template="Analyze: {sql_query}",
        ...     required_variables=frozenset({"sql_query"})
        ... )
        >>> builder.register_template(template)
        >>> prompt = builder.build_prompt(
        ...     "sql_analysis",
        ...     {"sql_query": "SELECT * FROM users"}
        ... )
        >>> print(prompt.get_full_prompt())
    """

    # Regex for detecting variable placeholders
    _VARIABLE_PATTERN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

    def __init__(self) -> None:
        """Initialize the PromptBuilder with empty template storage."""
        self._templates: dict[str, PromptTemplate] = {}
        self._lock = threading.RLock()
        self._builtin_templates = self._create_builtin_templates()

        # Register built-in templates
        for template in self._builtin_templates:
            self._templates[template.name] = template

    def register_template(self, template: PromptTemplate) -> None:
        """
        Register a new prompt template.

        Args:
            template: PromptTemplate to register

        Raises:
            InvalidTemplateError: If template is invalid
            ValueError: If template name already exists
        """
        if not template:
            raise InvalidTemplateError("Template cannot be None")

        with self._lock:
            if template.name in self._templates:
                raise ValueError(f"Template '{template.name}' already exists")

            self._templates[template.name] = template

    def unregister_template(self, name: str) -> bool:
        """
        Unregister a template.

        Args:
            name: Name of the template to remove

        Returns:
            True if template was removed, False if not found
        """
        with self._lock:
            # Check if it's a built-in template (by checking if it's in _builtin_templates)
            builtin_names = {t.name for t in self._builtin_templates}
            if name in builtin_names:
                raise ValueError(f"Cannot unregister built-in template '{name}'")
            return self._templates.pop(name, None) is not None

    def get_template(self, name: str) -> PromptTemplate | None:
        """
        Get a template by name.

        Args:
            name: Name of the template

        Returns:
            PromptTemplate or None if not found
        """
        with self._lock:
            return self._templates.get(name)

    def get_all_templates(self) -> list[PromptTemplate]:
        """
        Get all registered templates.

        Returns:
            List of all registered templates
        """
        with self._lock:
            return list(self._templates.values())

    def template_exists(self, name: str) -> bool:
        """
        Check if a template exists.

        Args:
            name: Name of the template

        Returns:
            True if template exists
        """
        with self._lock:
            return name in self._templates

    def build_prompt(
        self,
        template_name: str,
        variables: dict[str, Any],
        escape_strategy: EscapeStrategy | None = None,
        strict_validation: bool = True,
    ) -> Prompt:
        """
        Build a prompt from a template.

        Args:
            template_name: Name of the template to use
            variables: Variables to render in the template
            escape_strategy: Override default escape strategy
            strict_validation: If True, raise error for missing required variables

        Returns:
            Rendered Prompt object

        Raises:
            TemplateNotFoundError: If template not found
            MissingVariableError: If required variable is missing
            UnsafeValueError: If a value contains unsafe content
            InvalidTemplateError: If template rendering fails
        """
        template = self.get_template(template_name)
        if template is None:
            raise TemplateNotFoundError(f"Template '{template_name}' not found")

        # Validate variables
        self._validate_variables(template, variables, strict_validation)

        # Sanitize variables
        sanitized_vars = self._sanitize_variables(
            variables,
            escape_strategy or template.escape_strategy,
        )

        # Render user prompt with all variables (including required ones with defaults if not strict)
        try:
            user_prompt = self._render_template_with_defaults(
                template.user_prompt_template,
                sanitized_vars,
                template.required_variables,
                template.optional_variables,
                strict_validation,
            )
        except KeyError as e:
            raise InvalidTemplateError(f"Missing variable in template: {e}")

        # Render system prompt if present
        system_prompt = None
        if template.system_prompt:
            try:
                system_prompt = self._render_template_with_defaults(
                    template.system_prompt,
                    sanitized_vars,
                    template.required_variables,
                    template.optional_variables,
                    strict_validation,
                )
            except KeyError as e:
                raise InvalidTemplateError(f"Missing variable in system prompt: {e}")

        # Build prompt object
        return Prompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            template_name=template_name,
            variables=variables,
            prompt_type=template.prompt_type,
            rendered_at=time.time(),
        )

    def build_sql_injection_prompt(
        self,
        sql_query: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build a SQL injection analysis prompt.

        Args:
            sql_query: The SQL query to analyze
            context: Additional context about the query
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "sql_query": sql_query,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("sql_injection_analysis", variables)

    def build_xss_analysis_prompt(
        self,
        code: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build an XSS analysis prompt.

        Args:
            code: The code to analyze for XSS
            context: Additional context
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "code": code,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("xss_analysis", variables)

    def build_reverse_engineering_prompt(
        self,
        binary_info: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build a reverse engineering analysis prompt.

        Args:
            binary_info: Information about the binary
            context: Additional context
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "binary_info": binary_info,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("reverse_engineering", variables)

    def build_malware_analysis_prompt(
        self,
        malware_info: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build a malware analysis prompt.

        Args:
            malware_info: Information about the malware
            context: Additional context
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "malware_info": malware_info,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("malware_analysis", variables)

    def build_vulnerability_explanation_prompt(
        self,
        vulnerability: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build a vulnerability explanation prompt.

        Args:
            vulnerability: The vulnerability to explain
            context: Additional context
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "vulnerability": vulnerability,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("vulnerability_explanation", variables)

    def build_security_report_prompt(
        self,
        report_data: str,
        context: str | None = None,
        additional_analysis: str | None = None,
    ) -> Prompt:
        """
        Build a security report prompt.

        Args:
            report_data: The data for the report
            context: Additional context
            additional_analysis: Additional analysis to include

        Returns:
            Rendered Prompt object
        """
        variables = {
            "report_data": report_data,
            "context": context or "No additional context provided",
            "additional_analysis": additional_analysis or "No additional analysis",
        }
        return self.build_prompt("security_report", variables)

    def get_builtin_templates(self) -> list[PromptTemplate]:
        """
        Get the built-in templates.

        Returns:
            List of built-in PromptTemplate objects
        """
        return self._builtin_templates

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _create_builtin_templates(self) -> list[PromptTemplate]:
        """
        Create the built-in prompt templates.

        Returns:
            List of built-in PromptTemplate objects
        """
        return [
            PromptTemplate(
                name="sql_injection_analysis",
                prompt_type=PromptType.SQL_INJECTION_ANALYSIS,
                system_prompt="You are a senior security engineer specializing in SQL injection analysis.",
                user_prompt_template="""
SQL Injection Analysis

Analyze the following SQL query for potential injection vulnerabilities:

SQL Query:
{sql_query}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive analysis including:
1. Vulnerability assessment
2. Risk level
3. Recommended fixes
4. Exploitation vectors if applicable
                """.strip(),
                description="Analyze SQL queries for injection vulnerabilities",
                required_variables=frozenset({"sql_query"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.SQL,
                tags=frozenset({"sql", "security", "analysis"}),
            ),
            PromptTemplate(
                name="xss_analysis",
                prompt_type=PromptType.XSS_ANALYSIS,
                system_prompt="You are a senior security engineer specializing in XSS detection.",
                user_prompt_template="""
Cross-Site Scripting (XSS) Analysis

Analyze the following code for potential XSS vulnerabilities:

Code:
{code}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive analysis including:
1. XSS vulnerability assessment
2. Risk level
3. Recommended fixes
4. Attack vectors
                """.strip(),
                description="Analyze code for XSS vulnerabilities",
                required_variables=frozenset({"code"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.HTML,
                tags=frozenset({"xss", "security", "analysis"}),
            ),
            PromptTemplate(
                name="reverse_engineering",
                prompt_type=PromptType.REVERSE_ENGINEERING,
                system_prompt="You are a senior reverse engineer specializing in binary analysis.",
                user_prompt_template="""
Reverse Engineering Analysis

Analyze the following binary information:

Binary Info:
{binary_info}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive analysis including:
1. Binary structure
2. Potential vulnerabilities
3. Interesting functions
4. Security implications
                """.strip(),
                description="Analyze binary for reverse engineering",
                required_variables=frozenset({"binary_info"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.NONE,
                tags=frozenset({"reverse", "binary", "analysis"}),
            ),
            PromptTemplate(
                name="malware_analysis",
                prompt_type=PromptType.MALWARE_ANALYSIS,
                system_prompt="You are a senior malware analyst specializing in threat detection.",
                user_prompt_template="""
Malware Analysis

Analyze the following malware information:

Malware Info:
{malware_info}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive analysis including:
1. Malware classification
2. Behavior analysis
3. Indicators of Compromise (IOCs)
4. Mitigation strategies
                """.strip(),
                description="Analyze malware for threats",
                required_variables=frozenset({"malware_info"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.NONE,
                tags=frozenset({"malware", "threat", "analysis"}),
            ),
            PromptTemplate(
                name="vulnerability_explanation",
                prompt_type=PromptType.VULNERABILITY_EXPLANATION,
                system_prompt="You are a senior security engineer specializing in vulnerability explanation.",
                user_prompt_template="""
Vulnerability Explanation

Explain the following vulnerability:

Vulnerability:
{vulnerability}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive explanation including:
1. Vulnerability description
2. Technical details
3. Impact assessment
4. Remediation steps
                """.strip(),
                description="Explain vulnerabilities in detail",
                required_variables=frozenset({"vulnerability"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.NONE,
                tags=frozenset({"vulnerability", "explanation"}),
            ),
            PromptTemplate(
                name="security_report",
                prompt_type=PromptType.SECURITY_REPORT,
                system_prompt="You are a senior security engineer specializing in security reporting.",
                user_prompt_template="""
Security Report

Generate a security report based on the following data:

Report Data:
{report_data}

Context:
{context}

Additional Analysis:
{additional_analysis}

Please provide a comprehensive report including:
1. Executive summary
2. Detailed findings
3. Risk assessment
4. Recommendations
                """.strip(),
                description="Generate security reports",
                required_variables=frozenset({"report_data"}),
                optional_variables=frozenset({"context", "additional_analysis"}),
                escape_strategy=EscapeStrategy.NONE,
                tags=frozenset({"report", "security"}),
            ),
        ]

    def _validate_variables(
        self,
        template: PromptTemplate,
        variables: dict[str, Any],
        strict: bool,
    ) -> None:
        """
        Validate that all required variables are present.

        Args:
            template: PromptTemplate to validate against
            variables: Variables to validate
            strict: If True, raise error for missing required variables

        Raises:
            MissingVariableError: If a required variable is missing and strict=True
        """
        if not strict:
            return

        missing = []
        for required in template.required_variables:
            if required not in variables or variables[required] is None:
                missing.append(required)

        if missing:
            raise MissingVariableError(
                f"Missing required variables: {', '.join(missing)}"
            )

    def _sanitize_variables(
        self,
        variables: dict[str, Any],
        escape_strategy: EscapeStrategy,
    ) -> dict[str, str]:
        """
        Sanitize variables by escaping unsafe values.

        Args:
            variables: Variables to sanitize
            escape_strategy: Escape strategy to apply

        Returns:
            Sanitized variables as strings

        Raises:
            UnsafeValueError: If a value contains unsafe content
        """
        sanitized = {}

        for key, value in variables.items():
            if value is None:
                sanitized[key] = ""
                continue

            # Convert to string
            str_value = str(value)

            # Apply escape strategy
            escaped = self._escape_value(str_value, escape_strategy)

            # Check for unsafe content if using strict mode
            if escape_strategy != EscapeStrategy.NONE:
                self._check_unsafe_content(escaped)

            sanitized[key] = escaped

        return sanitized

    def _escape_value(self, value: str, strategy: EscapeStrategy) -> str:
        """
        Escape a value using the specified strategy.

        Args:
            value: Value to escape
            strategy: Escape strategy to use

        Returns:
            Escaped value
        """
        if strategy == EscapeStrategy.HTML:
            return html.escape(value)
        elif strategy == EscapeStrategy.XML:
            return xml_utils.escape(value)
        elif strategy == EscapeStrategy.JSON:
            return json.dumps(value, ensure_ascii=False)
        elif strategy == EscapeStrategy.SQL:
            return self._escape_sql(value)
        elif strategy == EscapeStrategy.SHELL:
            return self._escape_shell(value)
        else:
            return value

    def _escape_sql(self, value: str) -> str:
        """
        Escape a value for SQL context.

        Args:
            value: Value to escape

        Returns:
            SQL-escaped value
        """
        # Escape single quotes by doubling them
        escaped = value.replace("'", "''")
        # Escape backslashes
        escaped = escaped.replace("\\", "\\\\")
        return escaped

    def _escape_shell(self, value: str) -> str:
        """
        Escape a value for shell context.

        Args:
            value: Value to escape

        Returns:
            Shell-escaped value
        """
        # Escape characters that have special meaning in shell
        unsafe_chars = r"[;&|`$(){}[]<>*?!\n\r\t\v\f]"
        return re.sub(unsafe_chars, r"\\\g<0>", value)

    def _check_unsafe_content(self, value: str) -> None:
        """
        Check if a value contains unsafe content.

        Args:
            value: Value to check

        Raises:
            UnsafeValueError: If unsafe content is detected
        """
        # Common unsafe patterns
        unsafe_patterns = [
            (r"<\s*script\s*>", "Potential script injection detected"),
            (r"<\s*iframe\s*>", "Potential iframe injection detected"),
            (r"javascript\s*:", "Potential javascript injection detected"),
            (r"data\s*:\s*text/html", "Potential data URI injection detected"),
        ]

        for pattern, message in unsafe_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise UnsafeValueError(f"Unsafe content detected: {message}")

    def _render_template_with_defaults(
        self,
        template: str,
        variables: dict[str, str],
        required_variables: frozenset[str],
        optional_variables: frozenset[str],
        strict: bool,
    ) -> str:
        """
        Render a template with variables, providing defaults for missing variables.

        Args:
            template: Template string with {variable} placeholders
            variables: Variables to substitute
            required_variables: Set of required variable names
            optional_variables: Set of optional variable names
            strict: If True, raise error for missing required variables

        Returns:
            Rendered template string

        Raises:
            KeyError: If a required variable is missing and strict=True
        """
        # Create a copy of variables with defaults for missing ones
        render_vars = dict(variables)

        # If not strict, provide empty string defaults for ALL missing variables
        if not strict:
            # Find all variables in the template
            all_template_vars = set(
                re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", template)
            )
            for var in all_template_vars:
                if var not in render_vars or render_vars[var] is None:
                    render_vars[var] = ""

        return template.format(**render_vars)
