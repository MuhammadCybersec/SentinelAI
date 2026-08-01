# tests/test_prompt_builder.py
"""
Unit tests for PromptBuilder.

This test suite provides 100% coverage for the PromptBuilder class.
Tests include:
- Template registration and retrieval
- Variable validation
- Template rendering
- Escape strategies
- Exception handling
- Thread safety
- Edge cases
"""

import os
import sys
import threading

import pytest

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.ai.prompt_builder import (
    EscapeStrategy,
    InvalidTemplateError,
    MissingVariableError,
    Prompt,
    PromptBuilder,
    PromptBuilderError,
    PromptTemplate,
    PromptType,
    TemplateNotFoundError,
    UnsafeValueError,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def builder() -> PromptBuilder:
    """Create a fresh PromptBuilder instance."""
    return PromptBuilder()


@pytest.fixture
def sample_template() -> PromptTemplate:
    """Create a sample template for testing."""
    return PromptTemplate(
        name="sample",
        prompt_type=PromptType.CUSTOM,
        system_prompt="System: {system_var}",
        user_prompt_template="User: {user_var}",
        required_variables=frozenset({"user_var"}),
        optional_variables=frozenset({"system_var"}),
        description="Sample template",
    )


@pytest.fixture
def builtin_template_names() -> list[str]:
    """Get names of built-in templates."""
    return [
        "sql_injection_analysis",
        "xss_analysis",
        "reverse_engineering",
        "malware_analysis",
        "vulnerability_explanation",
        "security_report",
    ]


# =============================================================================
# Test PromptTemplate
# =============================================================================


class TestPromptTemplate:
    """Tests for PromptTemplate dataclass."""

    def test_template_creation(self) -> None:
        """Test creating a valid template."""
        template = PromptTemplate(
            name="test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Hello {name}",
            required_variables=frozenset({"name"}),
        )
        assert template.name == "test"
        assert template.prompt_type == PromptType.CUSTOM
        assert template.user_prompt_template == "Hello {name}"
        assert "name" in template.required_variables

    def test_template_invalid_empty_name(self) -> None:
        """Test template with empty name raises error."""
        with pytest.raises(InvalidTemplateError, match="Template name cannot be empty"):
            PromptTemplate(
                name="",
                prompt_type=PromptType.CUSTOM,
                user_prompt_template="Hello {name}",
            )

    def test_template_invalid_empty_user_prompt(self) -> None:
        """Test template with empty user prompt raises error."""
        with pytest.raises(
            InvalidTemplateError, match="User prompt template cannot be empty"
        ):
            PromptTemplate(
                name="test",
                prompt_type=PromptType.CUSTOM,
                user_prompt_template="",
            )

    def test_template_invalid_system_prompt_empty(self) -> None:
        """Test template with empty system prompt raises error."""
        with pytest.raises(
            InvalidTemplateError, match="System prompt cannot be empty string"
        ):
            PromptTemplate(
                name="test",
                prompt_type=PromptType.CUSTOM,
                user_prompt_template="Hello {name}",
                system_prompt="",
            )

    def test_template_get_all_variables(self) -> None:
        """Test getting all variables from template."""
        template = PromptTemplate(
            name="test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Hello {name}",
            required_variables=frozenset({"name"}),
            optional_variables=frozenset({"age", "city"}),
        )
        variables = template.get_all_variables()
        assert "name" in variables
        assert "age" in variables
        assert "city" in variables
        assert len(variables) == 3


# =============================================================================
# Test Prompt
# =============================================================================


class TestPrompt:
    """Tests for Prompt dataclass."""

    def test_prompt_creation(self) -> None:
        """Test creating a prompt."""
        prompt = Prompt(
            system_prompt="System: Hello",
            user_prompt="User: World",
            template_name="test",
            variables={"name": "World"},
            prompt_type=PromptType.CUSTOM,
        )
        assert prompt.system_prompt == "System: Hello"
        assert prompt.user_prompt == "User: World"
        assert prompt.template_name == "test"

    def test_prompt_to_dict(self) -> None:
        """Test converting prompt to dictionary."""
        prompt = Prompt(
            system_prompt="System: Hello",
            user_prompt="User: World",
            template_name="test",
            variables={"name": "World"},
            prompt_type=PromptType.CUSTOM,
            rendered_at=1234567890.0,
        )
        data = prompt.to_dict()
        assert data["system_prompt"] == "System: Hello"
        assert data["user_prompt"] == "User: World"
        assert data["template_name"] == "test"
        assert data["prompt_type"] == "custom"
        assert data["rendered_at"] == 1234567890.0

    def test_prompt_get_full_prompt(self) -> None:
        """Test getting full prompt with system + user."""
        prompt = Prompt(
            system_prompt="System: Hello",
            user_prompt="User: World",
            template_name="test",
            variables={},
            prompt_type=PromptType.CUSTOM,
        )
        full = prompt.get_full_prompt()
        assert full == "System: Hello\n\nUser: World"

    def test_prompt_get_full_prompt_no_system(self) -> None:
        """Test getting full prompt without system prompt."""
        prompt = Prompt(
            system_prompt=None,
            user_prompt="User: World",
            template_name="test",
            variables={},
            prompt_type=PromptType.CUSTOM,
        )
        full = prompt.get_full_prompt()
        assert full == "User: World"


# =============================================================================
# Test PromptBuilder
# =============================================================================


class TestPromptBuilder:
    """Tests for PromptBuilder class."""

    def test_initialization(self, builder: PromptBuilder) -> None:
        """Test builder initialization."""
        assert builder is not None
        templates = builder.get_all_templates()
        assert len(templates) == 6  # 6 built-in templates

    def test_builtin_templates_exist(
        self,
        builder: PromptBuilder,
        builtin_template_names: list[str],
    ) -> None:
        """Test that built-in templates exist."""
        for name in builtin_template_names:
            template = builder.get_template(name)
            assert template is not None
            assert template.name == name

    def test_builtin_template_sql_injection(self, builder: PromptBuilder) -> None:
        """Test SQL injection built-in template."""
        template = builder.get_template("sql_injection_analysis")
        assert template is not None
        assert template.prompt_type == PromptType.SQL_INJECTION_ANALYSIS
        assert "sql_query" in template.required_variables

    def test_builtin_template_xss(self, builder: PromptBuilder) -> None:
        """Test XSS built-in template."""
        template = builder.get_template("xss_analysis")
        assert template is not None
        assert template.prompt_type == PromptType.XSS_ANALYSIS
        assert "code" in template.required_variables

    def test_register_template(self, builder: PromptBuilder) -> None:
        """Test registering a new template."""
        template = PromptTemplate(
            name="custom",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Custom: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)
        retrieved = builder.get_template("custom")
        assert retrieved is not None
        assert retrieved.name == "custom"

    def test_register_duplicate_template(self, builder: PromptBuilder) -> None:
        """Test registering duplicate template raises error."""
        template = PromptTemplate(
            name="custom",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Custom: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)
        with pytest.raises(ValueError, match="Template 'custom' already exists"):
            builder.register_template(template)

    def test_unregister_template(self, builder: PromptBuilder) -> None:
        """Test unregistering a template."""
        template = PromptTemplate(
            name="custom",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Custom: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)
        result = builder.unregister_template("custom")
        assert result is True
        assert builder.get_template("custom") is None

    def test_unregister_builtin_template(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test unregistering built-in template raises error."""
        with pytest.raises(
            ValueError,
            match="Cannot unregister built-in template 'sql_injection_analysis'",
        ):
            builder.unregister_template("sql_injection_analysis")

    def test_get_template_not_found(self, builder: PromptBuilder) -> None:
        """Test getting template that doesn't exist."""
        template = builder.get_template("nonexistent")
        assert template is None

    def test_template_exists(self, builder: PromptBuilder) -> None:
        """Test checking if template exists."""
        assert builder.template_exists("sql_injection_analysis") is True
        assert builder.template_exists("nonexistent") is False

    def test_build_prompt_success(self, builder: PromptBuilder) -> None:
        """Test successfully building a prompt."""
        # Provide all required and optional variables
        prompt = builder.build_prompt(
            "sql_injection_analysis",
            {
                "sql_query": "SELECT * FROM users",
                "context": "Test context for SQL injection",
                "additional_analysis": "No additional analysis",
            },
        )
        assert prompt is not None
        assert prompt.template_name == "sql_injection_analysis"
        assert "SELECT * FROM users" in prompt.user_prompt
        assert prompt.system_prompt is not None

    def test_build_prompt_with_optional_variables(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test building prompt with optional variables."""
        prompt = builder.build_prompt(
            "sql_injection_analysis",
            {
                "sql_query": "SELECT * FROM users",
                "context": "Test context",
                "additional_analysis": "Test analysis",
            },
        )
        assert prompt is not None
        assert "Test context" in prompt.user_prompt
        assert "Test analysis" in prompt.user_prompt

    def test_build_prompt_missing_required_variable(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test building prompt with missing required variable."""
        with pytest.raises(
            MissingVariableError, match="Missing required variables: sql_query"
        ):
            builder.build_prompt(
                "sql_injection_analysis",
                {},
                strict_validation=True,
            )

    def test_build_prompt_missing_required_variable_not_strict(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test building prompt with missing required variable (not strict)."""
        # When strict_validation=False, missing required variables are replaced with empty strings
        prompt = builder.build_prompt(
            "sql_injection_analysis",
            {},
            strict_validation=False,
        )
        assert prompt is not None
        # The template will render with empty string for missing variables
        assert "SQL Injection Analysis" in prompt.user_prompt
        # The sql_query placeholder should be replaced with empty string
        assert "SQL Query:" in prompt.user_prompt
        # The context placeholder should be replaced with empty string
        assert "Context:" in prompt.user_prompt

    def test_build_prompt_template_not_found(self, builder: PromptBuilder) -> None:
        """Test building prompt with template not found."""
        with pytest.raises(
            TemplateNotFoundError, match="Template 'nonexistent' not found"
        ):
            builder.build_prompt("nonexistent", {})

    def test_build_prompt_escape_html(self, builder: PromptBuilder) -> None:
        """Test HTML escape strategy."""
        template = PromptTemplate(
            name="html_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
            escape_strategy=EscapeStrategy.HTML,
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "html_test",
            {"value": "<script>alert('xss')</script>"},
        )
        assert "&lt;script&gt;" in prompt.user_prompt
        assert "<script>" not in prompt.user_prompt

    def test_build_prompt_escape_sql(self, builder: PromptBuilder) -> None:
        """Test SQL escape strategy."""
        template = PromptTemplate(
            name="sql_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
            escape_strategy=EscapeStrategy.SQL,
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "sql_test",
            {"value": "O'Reilly"},
        )
        assert "O''Reilly" in prompt.user_prompt

    def test_build_prompt_escape_json(self, builder: PromptBuilder) -> None:
        """Test JSON escape strategy."""
        template = PromptTemplate(
            name="json_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
            escape_strategy=EscapeStrategy.JSON,
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "json_test",
            {"value": "Hello\nWorld"},
        )
        assert '"Hello\\nWorld"' in prompt.user_prompt

    def test_build_prompt_escape_none(self, builder: PromptBuilder) -> None:
        """Test no escape strategy."""
        template = PromptTemplate(
            name="none_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
            escape_strategy=EscapeStrategy.NONE,
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "none_test",
            {"value": "<script>alert('xss')</script>"},
        )
        assert "<script>alert('xss')</script>" in prompt.user_prompt

    def test_build_prompt_override_escape_strategy(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test overriding escape strategy."""
        template = PromptTemplate(
            name="override_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
            escape_strategy=EscapeStrategy.NONE,
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "override_test",
            {"value": "<script>"},
            escape_strategy=EscapeStrategy.HTML,
        )
        assert "&lt;script&gt;" in prompt.user_prompt

    def test_build_prompt_none_value(self, builder: PromptBuilder) -> None:
        """Test building prompt with None value."""
        template = PromptTemplate(
            name="none_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)
        prompt = builder.build_prompt(
            "none_test",
            {"value": None},
            strict_validation=False,
        )
        # None should be converted to empty string
        assert "Value: " in prompt.user_prompt

    def test_build_sql_injection_prompt(self, builder: PromptBuilder) -> None:
        """Test building SQL injection prompt."""
        prompt = builder.build_sql_injection_prompt(
            sql_query="SELECT * FROM users",
            context="Test context",
            additional_analysis="Test analysis",
        )
        assert prompt.prompt_type == PromptType.SQL_INJECTION_ANALYSIS
        assert "SELECT * FROM users" in prompt.user_prompt
        assert "Test context" in prompt.user_prompt

    def test_build_xss_analysis_prompt(self, builder: PromptBuilder) -> None:
        """Test building XSS analysis prompt."""
        prompt = builder.build_xss_analysis_prompt(
            code="<script>alert('xss')</script>",
            context="Test context",
        )
        assert prompt.prompt_type == PromptType.XSS_ANALYSIS
        assert "Test context" in prompt.user_prompt

    def test_build_reverse_engineering_prompt(self, builder: PromptBuilder) -> None:
        """Test building reverse engineering prompt."""
        prompt = builder.build_reverse_engineering_prompt(
            binary_info="Binary: test.exe",
            context="Test context",
        )
        assert prompt.prompt_type == PromptType.REVERSE_ENGINEERING
        assert "Binary: test.exe" in prompt.user_prompt

    def test_build_malware_analysis_prompt(self, builder: PromptBuilder) -> None:
        """Test building malware analysis prompt."""
        prompt = builder.build_malware_analysis_prompt(
            malware_info="Malware: Trojan",
            context="Test context",
        )
        assert prompt.prompt_type == PromptType.MALWARE_ANALYSIS
        assert "Malware: Trojan" in prompt.user_prompt

    def test_build_vulnerability_explanation_prompt(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test building vulnerability explanation prompt."""
        prompt = builder.build_vulnerability_explanation_prompt(
            vulnerability="SQL Injection",
            context="Test context",
        )
        assert prompt.prompt_type == PromptType.VULNERABILITY_EXPLANATION
        assert "SQL Injection" in prompt.user_prompt

    def test_build_security_report_prompt(self, builder: PromptBuilder) -> None:
        """Test building security report prompt."""
        prompt = builder.build_security_report_prompt(
            report_data="Report: Security scan",
            context="Test context",
        )
        assert prompt.prompt_type == PromptType.SECURITY_REPORT
        assert "Report: Security scan" in prompt.user_prompt

    def test_get_builtin_templates(self, builder: PromptBuilder) -> None:
        """Test getting built-in templates."""
        templates = builder.get_builtin_templates()
        assert len(templates) == 6
        names = [t.name for t in templates]
        assert "sql_injection_analysis" in names
        assert "xss_analysis" in names
        assert "reverse_engineering" in names
        assert "malware_analysis" in names
        assert "vulnerability_explanation" in names
        assert "security_report" in names

    def test_get_all_templates(self, builder: PromptBuilder) -> None:
        """Test getting all templates."""
        # Register a custom template
        template = PromptTemplate(
            name="custom",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Custom: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        all_templates = builder.get_all_templates()
        assert len(all_templates) == 7  # 6 built-in + 1 custom
        names = [t.name for t in all_templates]
        assert "custom" in names


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for PromptBuilder."""

    def test_empty_variables(self, builder: PromptBuilder) -> None:
        """Test with empty variables."""
        template = PromptTemplate(
            name="empty_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="No variables",
            required_variables=frozenset(),
        )
        builder.register_template(template)
        prompt = builder.build_prompt("empty_test", {})
        assert prompt.user_prompt == "No variables"

    def test_template_with_no_system_prompt(self, builder: PromptBuilder) -> None:
        """Test template with no system prompt."""
        template = PromptTemplate(
            name="no_system",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="User: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)
        prompt = builder.build_prompt("no_system", {"value": "test"})
        assert prompt.system_prompt is None
        assert prompt.get_full_prompt() == "User: test"

    def test_special_characters_in_variables(self, builder: PromptBuilder) -> None:
        """Test special characters in variables."""
        template = PromptTemplate(
            name="special_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        special = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        prompt = builder.build_prompt("special_test", {"value": special})
        assert special in prompt.user_prompt

    def test_long_string_variable(self, builder: PromptBuilder) -> None:
        """Test long string variable."""
        template = PromptTemplate(
            name="long_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        long_string = "A" * 10000
        prompt = builder.build_prompt("long_test", {"value": long_string})
        assert long_string in prompt.user_prompt

    def test_unicode_in_variables(self, builder: PromptBuilder) -> None:
        """Test Unicode characters in variables."""
        template = PromptTemplate(
            name="unicode_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        unicode_str = "你好世界 🌍"
        prompt = builder.build_prompt("unicode_test", {"value": unicode_str})
        assert unicode_str in prompt.user_prompt

    def test_boolean_variable(self, builder: PromptBuilder) -> None:
        """Test boolean variable."""
        template = PromptTemplate(
            name="bool_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        prompt = builder.build_prompt("bool_test", {"value": True})
        assert "True" in prompt.user_prompt

    def test_numeric_variable(self, builder: PromptBuilder) -> None:
        """Test numeric variable."""
        template = PromptTemplate(
            name="num_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        prompt = builder.build_prompt("num_test", {"value": 42})
        assert "42" in prompt.user_prompt

    def test_list_variable(self, builder: PromptBuilder) -> None:
        """Test list variable."""
        template = PromptTemplate(
            name="list_test",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        prompt = builder.build_prompt("list_test", {"value": [1, 2, 3]})
        assert "[1, 2, 3]" in prompt.user_prompt


# =============================================================================
# Test Thread Safety
# =============================================================================


class TestThreadSafety:
    """Thread safety tests for PromptBuilder."""

    def test_concurrent_template_registration(self, builder: PromptBuilder) -> None:
        """Test concurrent template registration."""

        def register_template(index: int) -> None:
            template = PromptTemplate(
                name=f"concurrent_{index}",
                prompt_type=PromptType.CUSTOM,
                user_prompt_template=f"Template {index}: {{value}}",
                required_variables=frozenset({"value"}),
            )
            builder.register_template(template)

        threads = []
        for i in range(10):
            t = threading.Thread(target=register_template, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Verify all templates were registered
        for i in range(10):
            assert builder.template_exists(f"concurrent_{i}") is True

    def test_concurrent_prompt_building(self, builder: PromptBuilder) -> None:
        """Test concurrent prompt building."""
        template = PromptTemplate(
            name="concurrent_build",
            prompt_type=PromptType.CUSTOM,
            user_prompt_template="Value: {value}",
            required_variables=frozenset({"value"}),
        )
        builder.register_template(template)

        results: list[Prompt] = []

        def build_prompt(index: int) -> None:
            prompt = builder.build_prompt(
                "concurrent_build",
                {"value": f"test_{index}"},
            )
            results.append(prompt)

        threads = []
        for i in range(10):
            t = threading.Thread(target=build_prompt, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(results) == 10
        values = [p.variables["value"] for p in results]
        assert "test_0" in values
        assert "test_9" in values

    def test_concurrent_read_write(self, builder: PromptBuilder) -> None:
        """Test concurrent read and write operations."""
        # Use a lock to prevent duplicate template registration
        register_lock = threading.Lock()
        registered = set()

        def register_template(index: int) -> None:
            with register_lock:
                name = f"rw_{index}"
                if name in registered:
                    return
                template = PromptTemplate(
                    name=name,
                    prompt_type=PromptType.CUSTOM,
                    user_prompt_template=f"RW {index}: {{value}}",
                    required_variables=frozenset({"value"}),
                )
                builder.register_template(template)
                registered.add(name)

        def get_template(index: int) -> None:
            builder.get_template(f"rw_{index}")

        def build_prompt(index: int) -> None:
            try:
                builder.build_prompt(f"rw_{index}", {"value": "test"})
            except TemplateNotFoundError:
                pass  # Expected if template not yet registered

        threads = []
        for i in range(20):
            for action in [register_template, get_template, build_prompt]:
                t = threading.Thread(target=action, args=(i % 10,))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        # Verify templates were registered
        for i in range(10):
            assert builder.template_exists(f"rw_{i}") is True


# =============================================================================
# Test Exceptions
# =============================================================================


class TestExceptions:
    """Exception tests for PromptBuilder."""

    def test_prompt_builder_error_base(self) -> None:
        """Test base exception."""
        error = PromptBuilderError("Test error")
        assert str(error) == "Test error"

    def test_template_not_found_error(self) -> None:
        """Test template not found exception."""
        error = TemplateNotFoundError("Template not found")
        assert "Template not found" in str(error)

    def test_missing_variable_error(self) -> None:
        """Test missing variable exception."""
        error = MissingVariableError("Missing variable: name")
        assert "Missing variable: name" in str(error)

    def test_invalid_template_error(self) -> None:
        """Test invalid template exception."""
        error = InvalidTemplateError("Invalid template format")
        assert "Invalid template format" in str(error)

    def test_unsafe_value_error(self) -> None:
        """Test unsafe value exception."""
        error = UnsafeValueError("Unsafe content detected: script")
        assert "Unsafe content detected: script" in str(error)


# =============================================================================
# Test Integration
# =============================================================================


class TestIntegration:
    """Integration tests for PromptBuilder."""

    def test_full_workflow(self, builder: PromptBuilder) -> None:
        """Test full workflow from registration to rendering."""
        # Create template
        template = PromptTemplate(
            name="full_workflow",
            prompt_type=PromptType.CUSTOM,
            system_prompt="System: {system_var}",
            user_prompt_template="User: {user_var}",
            required_variables=frozenset({"user_var"}),
            optional_variables=frozenset({"system_var"}),
        )

        # Register
        builder.register_template(template)
        assert builder.template_exists("full_workflow") is True

        # Build prompt
        prompt = builder.build_prompt(
            "full_workflow",
            {
                "system_var": "Hello system",
                "user_var": "Hello user",
            },
        )

        # Verify
        assert prompt.system_prompt == "System: Hello system"
        assert prompt.user_prompt == "User: Hello user"
        assert prompt.template_name == "full_workflow"
        assert prompt.prompt_type == PromptType.CUSTOM

        # Get full prompt
        full = prompt.get_full_prompt()
        assert "System: Hello system" in full
        assert "User: Hello user" in full

    def test_multiple_template_workflow(self, builder: PromptBuilder) -> None:
        """Test workflow with multiple templates."""
        # Register multiple templates
        for i in range(3):
            template = PromptTemplate(
                name=f"multi_{i}",
                prompt_type=PromptType.CUSTOM,
                user_prompt_template=f"Template {i}: {{value}}",
                required_variables=frozenset({"value"}),
            )
            builder.register_template(template)

        # Build prompts for all templates
        prompts = []
        for i in range(3):
            prompt = builder.build_prompt(f"multi_{i}", {"value": f"test_{i}"})
            prompts.append(prompt)

        assert len(prompts) == 3
        for i, prompt in enumerate(prompts):
            assert f"Template {i}: test_{i}" in prompt.user_prompt

    def test_builtin_templates_workflow(
        self,
        builder: PromptBuilder,
    ) -> None:
        """Test workflow with built-in templates."""
        # Build SQL injection prompt
        sql_prompt = builder.build_sql_injection_prompt(
            sql_query="SELECT * FROM users WHERE id = 1",
            context="User input validation",
            additional_analysis="No additional analysis",
        )
        assert sql_prompt.prompt_type == PromptType.SQL_INJECTION_ANALYSIS
        assert "SELECT * FROM users" in sql_prompt.user_prompt

        # Build XSS prompt
        xss_prompt = builder.build_xss_analysis_prompt(
            code="<script>alert('xss')</script>",
            context="User input validation",
        )
        assert xss_prompt.prompt_type == PromptType.XSS_ANALYSIS
        assert "alert" in xss_prompt.user_prompt
