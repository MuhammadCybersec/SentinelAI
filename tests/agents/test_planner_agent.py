"""
Tests for Planner Agent - Intelligent scanner selection for SentinelAI.
"""

import logging
from unittest.mock import patch

import pytest

from app.agents.planner_agent import (
    FormField,
    FormInfo,
    PlannerAgent,
    TargetAnalysis,
)


class TestFormField:
    """Tests for FormField dataclass."""

    def test_form_field_creation(self) -> None:
        """Test FormField creation with defaults."""
        field = FormField(name="username")
        assert field.name == "username"
        assert field.type == "text"
        assert field.value == ""
        assert field.required is False

    def test_form_field_with_values(self) -> None:
        """Test FormField with all values."""
        field = FormField(
            name="password", type="password", value="secret", required=True
        )
        assert field.name == "password"
        assert field.type == "password"
        assert field.value == "secret"
        assert field.required is True


class TestFormInfo:
    """Tests for FormInfo dataclass."""

    def test_form_info_creation(self) -> None:
        """Test FormInfo creation with defaults."""
        form = FormInfo()
        assert form.action == ""
        assert form.method == "GET"
        assert form.fields == []
        assert form.id == ""
        assert form.name == ""

    def test_form_info_with_fields(self) -> None:
        """Test FormInfo with fields."""
        fields = [
            FormField(name="email", type="email"),
            FormField(name="password", type="password"),
        ]
        form = FormInfo(
            action="/login", method="POST", fields=fields, id="login-form", name="login"
        )
        assert form.action == "/login"
        assert form.method == "POST"
        assert len(form.fields) == 2
        assert form.id == "login-form"
        assert form.name == "login"


class TestTargetAnalysis:
    """Tests for TargetAnalysis dataclass."""

    def test_target_analysis_creation(self) -> None:
        """Test TargetAnalysis creation."""
        analysis = TargetAnalysis(
            target="https://example.com",
            technologies=["python", "flask"],
            parameters=["id", "page"],
            recommended_scanners=["xss", "sqli"],
        )
        assert analysis.target == "https://example.com"
        assert len(analysis.technologies) == 2
        assert len(analysis.parameters) == 2
        assert len(analysis.recommended_scanners) == 2


class TestPlannerAgent:
    """Tests for PlannerAgent class."""

    @pytest.fixture
    def agent(self) -> PlannerAgent:
        """Create a PlannerAgent instance."""
        return PlannerAgent()

    @pytest.fixture
    def sample_html(self) -> str:
        """Sample HTML content with forms."""
        return """
        <html>
        <body>
            <form action="/search" method="GET" id="search-form">
                <input type="text" name="q" value="test">
                <input type="hidden" name="csrf" value="token">
                <input type="submit" value="Search">
            </form>
            <form action="/login" method="POST" name="login">
                <input type="text" name="username" required>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """

    def test_init_defaults(self, agent: PlannerAgent) -> None:
        """Test initialization with defaults."""
        assert agent._logger is not None
        assert agent._target is None
        assert agent._analysis is None

    def test_init_with_logger(self) -> None:
        """Test initialization with custom logger."""
        logger = logging.getLogger("test_logger")
        agent = PlannerAgent(logger=logger)
        assert agent._logger is logger

    def test_setup_logger(self, agent: PlannerAgent) -> None:
        """Test logger setup."""
        logger = agent._setup_logger(logging.DEBUG)
        assert logger.level == logging.DEBUG
        assert logger.name == "PlannerAgent"

    def test_analyze_target_valid_url(self, agent: PlannerAgent) -> None:
        """Test analyzing a valid URL."""
        url = "https://example.com/page?id=1&search=test"
        analysis = agent.analyze_target(url)

        assert analysis.target == url
        assert "id" in analysis.parameters
        assert "search" in analysis.parameters
        assert analysis.technologies == []
        assert analysis.forms == []

    def test_analyze_target_invalid_url(self, agent: PlannerAgent) -> None:
        """Test analyzing an invalid URL."""
        with pytest.raises(ValueError, match="Invalid URL"):
            agent.analyze_target("not-a-url")

    def test_analyze_target_no_params(self, agent: PlannerAgent) -> None:
        """Test analyzing URL with no parameters."""
        url = "https://example.com/"
        analysis = agent.analyze_target(url)
        assert analysis.parameters == []

    def test_detect_technologies_empty(self, agent: PlannerAgent) -> None:
        """Test detecting technologies from empty HTML."""
        result = agent.detect_technologies("")
        assert result == []

    def test_detect_technologies_jquery(self, agent: PlannerAgent) -> None:
        """Test detecting jQuery in HTML."""
        html = '<script src="jquery.min.js"></script>'
        result = agent.detect_technologies(html)
        assert "jquery" in result

    def test_detect_technologies_react(self, agent: PlannerAgent) -> None:
        """Test detecting React in HTML."""
        html = '<script src="react.min.js"></script>'
        result = agent.detect_technologies(html)
        assert "react" in result

    def test_detect_technologies_django(self, agent: PlannerAgent) -> None:
        """Test detecting Django in HTML."""
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="token">'
        result = agent.detect_technologies(html)
        assert "django" in result

    def test_detect_technologies_wordpress(self, agent: PlannerAgent) -> None:
        """Test detecting WordPress in HTML."""
        html = '<link rel="stylesheet" href="/wp-content/style.css">'
        result = agent.detect_technologies(html)
        assert "wordpress" in result

    def test_extract_parameters_single_url(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from a single URL."""
        urls = ["https://example.com/page?id=1&search=test&page=2"]
        result = agent.extract_parameters(urls)
        assert sorted(result) == ["id", "page", "search"]

    def test_extract_parameters_multiple_urls(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from multiple URLs."""
        urls = [
            "https://example.com/page?id=1",
            "https://example.com/search?q=test&filter=active",
            "https://example.com/user?user_id=123",
        ]
        result = agent.extract_parameters(urls)
        assert sorted(result) == ["filter", "id", "q", "user_id"]

    def test_extract_parameters_empty(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from empty URL list."""
        result = agent.extract_parameters([])
        assert result == []

    def test_extract_parameters_invalid_url(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from invalid URLs."""
        urls = ["not-a-url", "https://example.com/"]
        result = agent.extract_parameters(urls)
        assert result == []

    def test_extract_parameters_from_url(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from a single URL."""
        url = "https://test.com?id=1&search=abc"
        result = agent._extract_parameters_from_url(url)
        assert sorted(result) == ["id", "search"]

    def test_extract_parameters_from_url_no_params(self, agent: PlannerAgent) -> None:
        """Test extracting parameters from URL with no params."""
        url = "https://example.com/"
        result = agent._extract_parameters_from_url(url)
        assert result == []

    def test_extract_forms_basic(self, agent: PlannerAgent, sample_html: str) -> None:
        """Test extracting forms from HTML."""
        forms = agent.extract_forms(sample_html)
        assert len(forms) == 2

        # First form
        assert forms[0].action == "/search"
        assert forms[0].method == "GET"
        assert forms[0].id == "search-form"
        assert len(forms[0].fields) == 2
        assert forms[0].fields[0].name == "q"
        assert forms[0].fields[0].type == "text"
        assert forms[0].fields[1].name == "csrf"
        assert forms[0].fields[1].type == "hidden"

        # Second form
        assert forms[1].action == "/login"
        assert forms[1].method == "POST"
        assert forms[1].name == "login"
        assert len(forms[1].fields) == 2
        assert forms[1].fields[0].name == "username"
        assert forms[1].fields[0].required is True
        assert forms[1].fields[1].name == "password"
        assert forms[1].fields[1].required is True

    def test_extract_forms_empty_html(self, agent: PlannerAgent) -> None:
        """Test extracting forms from empty HTML."""
        forms = agent.extract_forms("")
        assert forms == []

    def test_choose_scanners_sqli(self, agent: PlannerAgent) -> None:
        """Test scanner selection for SQLi parameters."""
        parameters = ["id", "user_id", "product_id"]
        technologies = []
        result = agent.choose_scanners(parameters, technologies)
        assert "sqli" in result

    def test_choose_scanners_xss(self, agent: PlannerAgent) -> None:
        """Test scanner selection for XSS parameters."""
        parameters = ["search", "q", "query"]
        technologies = []
        result = agent.choose_scanners(parameters, technologies)
        assert "xss" in result

    def test_choose_scanners_path_traversal(self, agent: PlannerAgent) -> None:
        """Test scanner selection for path traversal parameters."""
        parameters = ["file", "path", "dir"]
        technologies = []
        result = agent.choose_scanners(parameters, technologies)
        assert "path_traversal" in result

    def test_choose_scanners_ssrf(self, agent: PlannerAgent) -> None:
        """Test scanner selection for SSRF parameters."""
        parameters = ["url", "redirect", "src"]
        technologies = []
        result = agent.choose_scanners(parameters, technologies)
        assert "ssrf" in result

    def test_choose_scanners_technology_mapping(self, agent: PlannerAgent) -> None:
        """Test scanner selection based on technologies."""
        parameters = []
        technologies = ["django", "postgresql"]
        result = agent.choose_scanners(parameters, technologies)
        assert "sqli" in result
        assert "xss" in result
        assert "csrf" in result

    def test_choose_scanners_forms(self, agent: PlannerAgent) -> None:
        """Test scanner selection based on form fields."""
        parameters = []
        technologies = []
        forms = [
            FormInfo(
                fields=[
                    FormField(name="id"),
                    FormField(name="search"),
                ]
            )
        ]
        result = agent.choose_scanners(parameters, technologies, forms)
        assert "sqli" in result
        assert "xss" in result

    def test_choose_scanners_duplicate_removal(self, agent: PlannerAgent) -> None:
        """Test duplicate scanner removal."""
        parameters = ["id", "user_id", "search", "q"]
        technologies = []
        result = agent.choose_scanners(parameters, technologies)
        # Should only have one "sqli" and one "xss"
        assert result.count("sqli") == 1
        assert result.count("xss") == 1

    def test_choose_scanners_forms_always_xss(self, agent: PlannerAgent) -> None:
        """Test forms always add XSS scanner."""
        parameters = []
        technologies = []
        forms = [
            FormInfo(
                fields=[
                    FormField(name="username"),
                    FormField(name="password"),
                ]
            )
        ]
        result = agent.choose_scanners(parameters, technologies, forms)
        assert "xss" in result

    def test_choose_scanners_empty(self, agent: PlannerAgent) -> None:
        """Test scanner selection with no input."""
        result = agent.choose_scanners([], [])
        assert result == []

    def test_choose_scanners_case_insensitive(self, agent: PlannerAgent) -> None:
        """Test scanner selection is case insensitive."""
        parameters = ["USER_ID", "Search", "FILE"]
        result = agent.choose_scanners(parameters, [])
        assert "sqli" in result
        assert "xss" in result
        assert "path_traversal" in result

    def test_choose_scanners_multiple_keywords(self, agent: PlannerAgent) -> None:
        """Test scanner selection with multiple keywords."""
        parameters = ["redirect_url", "file_path"]
        result = agent.choose_scanners(parameters, [])
        assert "open_redirect" in result
        assert "path_traversal" in result

    def test__choose_scanners_alias(self, agent: PlannerAgent) -> None:
        """Test _choose_scanners alias method."""
        parameters = ["id"]
        result1 = agent.choose_scanners(parameters, [])
        result2 = agent._choose_scanners(parameters, [])
        assert result1 == result2

    def test_get_analysis_none(self, agent: PlannerAgent) -> None:
        """Test get_analysis when no analysis performed."""
        result = agent.get_analysis()
        assert result is None

    def test_get_analysis_after_scan(self, agent: PlannerAgent) -> None:
        """Test get_analysis after scanning."""
        agent.analyze_target("https://example.com?id=1")
        result = agent.get_analysis()
        assert result is not None
        assert result.target == "https://example.com?id=1"

    def test_get_recommended_scanners_none(self, agent: PlannerAgent) -> None:
        """Test get_recommended_scanners when no analysis performed."""
        result = agent.get_recommended_scanners()
        assert result == []

    def test_get_recommended_scanners_after_scan(self, agent: PlannerAgent) -> None:
        """Test get_recommended_scanners after scanning."""
        agent.analyze_target("https://example.com?id=1&search=test")
        result = agent.get_recommended_scanners()
        assert "sqli" in result
        assert "xss" in result

    def test_reset(self, agent: PlannerAgent) -> None:
        """Test resetting the agent."""
        agent.analyze_target("https://example.com")
        assert agent._target is not None
        assert agent._analysis is not None

        agent.reset()
        assert agent._target is None
        assert agent._analysis is None

    def test_analyze_full_all_data(self, agent: PlannerAgent, sample_html: str) -> None:
        """Test complete analysis with all data."""
        url = "https://example.com/page?id=1&search=test"
        urls = ["https://example.com/other?user_id=123"]

        result = agent.analyze_full(url=url, html=sample_html, urls=urls)

        assert result.target == url
        assert "id" in result.parameters
        assert "search" in result.parameters
        assert "user_id" in result.parameters
        assert len(result.forms) == 2
        assert "sqli" in result.recommended_scanners
        assert "xss" in result.recommended_scanners

    def test_analyze_full_no_html(self, agent: PlannerAgent) -> None:
        """Test complete analysis without HTML."""
        url = "https://example.com?id=1"
        result = agent.analyze_full(url=url)
        assert result.technologies == []
        assert result.forms == []
        assert "sqli" in result.recommended_scanners

    def test_analyze_full_no_urls(self, agent: PlannerAgent) -> None:
        """Test complete analysis without additional URLs."""
        url = "https://example.com?id=1"
        result = agent.analyze_full(url=url)
        assert result.parameters == ["id"]

    def test_analyze_full_technologies_detected(self, agent: PlannerAgent) -> None:
        """Test complete analysis with technology detection."""
        html = '<script src="react.min.js"></script><input name="csrfmiddlewaretoken">'
        url = "https://example.com"

        result = agent.analyze_full(url=url, html=html)
        assert "react" in result.technologies
        assert "django" in result.technologies

    def test_analyze_full_merges_parameters(self, agent: PlannerAgent) -> None:
        """Test complete analysis merges parameters from multiple sources."""
        url = "https://example.com?id=1"
        urls = [
            "https://example.com/page?search=test",
            "https://example.com/user?user_id=123",
        ]

        result = agent.analyze_full(url=url, urls=urls)
        assert sorted(result.parameters) == ["id", "search", "user_id"]

    def test_logging_behavior(self, agent: PlannerAgent) -> None:
        """Test logging behavior."""
        with patch.object(agent._logger, "info") as mock_info:
            agent.analyze_target("https://example.com")
            mock_info.assert_called()

        with patch.object(agent._logger, "debug") as mock_debug:
            agent.detect_technologies("<html></html>")
            mock_debug.assert_called()

    def test_analyze_target_metadata(self, agent: PlannerAgent) -> None:
        """Test metadata in analysis result."""
        url = "https://example.com/page?id=1"
        analysis = agent.analyze_target(url)

        assert "parsed_url" in analysis.metadata
        assert analysis.metadata["parsed_url"]["scheme"] == "https"
        assert analysis.metadata["parsed_url"]["netloc"] == "example.com"
        assert analysis.metadata["parsed_url"]["path"] == "/page"
        assert analysis.metadata["parsed_url"]["query"] == "id=1"

    def test_extract_forms_with_no_action(self, agent: PlannerAgent) -> None:
        """Test extracting form with no action attribute."""
        html = '<form method="POST"><input name="test"></form>'
        forms = agent.extract_forms(html)
        assert len(forms) == 1
        assert forms[0].action == ""
        assert forms[0].method == "POST"

    def test_extract_forms_with_no_method(self, agent: PlannerAgent) -> None:
        """Test extracting form with no method attribute."""
        html = '<form action="/submit"><input name="test"></form>'
        forms = agent.extract_forms(html)
        assert len(forms) == 1
        assert forms[0].action == "/submit"
        assert forms[0].method == "GET"  # Default

    def test_extract_forms_with_no_fields(self, agent: PlannerAgent) -> None:
        """Test extracting form with no input fields."""
        html = '<form action="/submit" method="POST"></form>'
        forms = agent.extract_forms(html)
        assert len(forms) == 0  # No fields, skip

    def test_extract_forms_multiple_input_types(self, agent: PlannerAgent) -> None:
        """Test extracting forms with various input types."""
        html = """
        <form>
            <input type="text" name="text_field">
            <input type="hidden" name="hidden_field">
            <input type="password" name="password_field">
            <input type="email" name="email_field">
            <input type="number" name="number_field">
        </form>
        """
        forms = agent.extract_forms(html)
        assert len(forms) == 1
        assert len(forms[0].fields) == 5
        assert forms[0].fields[0].type == "text"
        assert forms[0].fields[1].type == "hidden"
        assert forms[0].fields[2].type == "password"
        assert forms[0].fields[3].type == "email"
        assert forms[0].fields[4].type == "number"
