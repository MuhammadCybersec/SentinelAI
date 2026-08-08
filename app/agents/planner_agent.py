"""
Planner Agent - Intelligent scanner selection for SentinelAI.

This module provides intelligent planning and scanner selection based on
target analysis, technology detection, and parameter extraction.
"""

from __future__ import annotations

import logging
import re
import typing
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

# ===========================================================
# Data Models
# ===========================================================


@dataclass(slots=True)
class FormField:
    """
    HTML form field information.

    Attributes:
        name: Field name
        type: Input type (text, password, hidden, etc.)
        value: Default value if present
        required: Whether field is required
    """

    name: str
    type: str = "text"
    value: str = ""
    required: bool = False


@dataclass(slots=True)
class FormInfo:
    """
    HTML form information.

    Attributes:
        action: Form action URL
        method: HTTP method (GET, POST)
        fields: List of form fields
        id: Form ID if present
        name: Form name if present
    """

    action: str = ""
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    id: str = ""
    name: str = ""


@dataclass(slots=True)
class TargetAnalysis:
    """
    Complete target analysis result.

    Attributes:
        target: Target URL
        technologies: Detected technologies
        parameters: Extracted URL parameters
        forms: Extracted HTML forms
        recommended_scanners: Recommended scanner names
        metadata: Additional metadata
    """

    target: str = ""
    technologies: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    recommended_scanners: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PlannerAgent:
    """
    Intelligent agent for planning security scans.

    Features:
        - Target analysis and profiling
        - Technology detection from HTML/headers
        - Parameter extraction from URLs
        - Form extraction from HTML
        - Smart scanner selection based on attack surface
        - Thread-safe logging
    """

    # Technology detection patterns
    TECH_PATTERNS: typing.ClassVar[dict[str, list[str]]] = {
        "jquery": [
            r"jquery[.-](\d+\.\d+\.\d+)",
            r"jquery\.min\.js",
            r"jquery-(\d+\.\d+\.\d+)\.min\.js",
        ],
        "react": [
            r"react\.min\.js",
            r"react-dom\.min\.js",
            r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
        ],
        "vue": [
            r"vue\.min\.js",
            r"vue-(\d+\.\d+\.\d+)\.min\.js",
            r"__VUE_DEVTOOLS_GLOBAL_HOOK__",
        ],
        "angular": [
            r"angular\.min\.js",
            r"ng-app",
            r"ng-controller",
            r"ng-model",
        ],
        "django": [
            r"csrfmiddlewaretoken",
            r"__cfduid",
            r"django\.contrib\.auth",
            r"django\.session",
        ],
        "flask": [
            r"flask-session",
            r"flask\.session",
            r"flask_wtf\.csrf",
        ],
        "wordpress": [
            r"wp-content",
            r"wp-includes",
            r"wp-admin",
            r"WordPress",
        ],
        "laravel": [
            r"laravel-session",
            r"_token",
            r"laravel\.php",
        ],
        "rails": [
            r"authenticity_token",
            r"rails\.session",
            r"rails-ujs",
        ],
        "aspnet": [
            r"__VIEWSTATE",
            r"__EVENTVALIDATION",
            r"aspnet\.session",
        ],
        "apache": [
            r"Apache/(\d+\.\d+\.\d+)",
            r"Apache Tomcat",
        ],
        "nginx": [
            r"nginx/(\d+\.\d+\.\d+)",
            r"nginx-",
        ],
        "iis": [
            r"Microsoft-IIS",
            r"ASP\.NET",
            r"\.aspx",
        ],
    }

    # Scanner selection rules
    SCANNER_RULES: typing.ClassVar[dict[str, list[str]]] = {
        "sqli": [
            "id",
            "user_id",
            "uid",
            "account_id",
            "profile_id",
            "order_id",
            "product_id",
            "category_id",
        ],
        "xss": [
            "search",
            "q",
            "query",
            "keyword",
            "term",
            "s",
            "filter",
            "page",
        ],
        "path_traversal": [
            "file",
            "path",
            "dir",
            "folder",
            "download",
            "view",
            "read",
            "include",
        ],
        "ssrf": [
            "url",
            "redirect",
            "link",
            "href",
            "src",
            "target",
            "callback",
            "dest",
            "return",
        ],
        "open_redirect": [
            "redirect",
            "return",
            "next",
            "dest",
            "destination",
            "goto",
            "continue",
            "callback",
            "target",
        ],
        "command_injection": [
            "cmd",
            "command",
            "exec",
            "run",
            "execute",
            "ping",
            "nslookup",
        ],
        "lfi": [
            "file",
            "path",
            "dir",
            "folder",
            "read",
            "view",
            "download",
        ],
        "rfi": [
            "file",
            "path",
            "url",
            "include",
            "require",
            "load",
        ],
    }

    # Technology to scanner mapping
    TECH_SCANNER_MAP: typing.ClassVar[dict[str, list[str]]] = {
        "django": ["sqli", "xss", "csrf"],
        "flask": ["sqli", "xss"],
        "wordpress": ["sqli", "xss", "lfi", "rfi"],
        "laravel": ["sqli", "xss", "csrf"],
        "rails": ["sqli", "xss", "csrf"],
        "aspnet": ["sqli", "xss", "path_traversal"],
        "apache": ["path_traversal", "lfi"],
        "nginx": ["path_traversal", "lfi"],
        "iis": ["path_traversal", "lfi"],
        "react": ["xss", "open_redirect"],
        "vue": ["xss", "open_redirect"],
        "angular": ["xss", "open_redirect"],
        "jquery": ["xss"],
    }

    def __init__(
        self,
        logger: logging.Logger | None = None,
        log_level: int = logging.INFO,
    ) -> None:
        """
        Initialize the Planner Agent.

        Args:
            logger: Optional logger instance
            log_level: Logging level (default: INFO)
        """
        self._logger = logger or self._setup_logger(log_level)
        self._target: str | None = None
        self._analysis: TargetAnalysis | None = None

    def _setup_logger(self, log_level: int) -> logging.Logger:
        """
        Set up a default logger.

        Args:
            log_level: Logging level

        Returns:
            Configured logger instance
        """
        logger = logging.getLogger("PlannerAgent")
        logger.setLevel(log_level)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def analyze_target(self, url: str) -> TargetAnalysis:
        """
        Analyze a target URL and return comprehensive analysis.

        Args:
            url: Target URL to analyze

        Returns:
            TargetAnalysis with all extracted information

        Raises:
            ValueError: If URL is invalid
        """
        self._logger.info(f"Analyzing target: {url}")
        self._target = url

        # Validate URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        # Extract parameters from URL
        parameters = self._extract_parameters_from_url(url)
        self._logger.debug(f"Extracted parameters: {parameters}")

        # Since we don't have the HTML content yet, we'll use placeholders
        # In production, this would fetch the page and parse it
        technologies: list[str] = []
        forms: list[FormInfo] = []

        self._analysis = TargetAnalysis(
            target=url,
            technologies=technologies,
            parameters=parameters,
            forms=forms,
            recommended_scanners=[],
            metadata={
                "parsed_url": {
                    "scheme": parsed.scheme,
                    "netloc": parsed.netloc,
                    "path": parsed.path,
                    "query": parsed.query,
                    "fragment": parsed.fragment,
                }
            },
        )

        # Choose scanners based on parameters and technologies
        self._analysis.recommended_scanners = self._choose_scanners(
            parameters=parameters, technologies=technologies, forms=forms
        )

        self._logger.info(
            f"Analysis complete: {len(parameters)} parameters, "
            f"{len(technologies)} technologies, "
            f"{len(self._analysis.recommended_scanners)} recommended scanners"
        )

        return self._analysis

    def detect_technologies(self, html: str) -> list[str]:
        """
        Detect technologies from HTML content.

        Args:
            html: HTML content to analyze

        Returns:
            List of detected technology names
        """
        self._logger.debug("Detecting technologies from HTML")
        detected: set[str] = set()

        if not html:
            return []

        html_lower = html.lower()

        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, html, re.IGNORECASE):
                        detected.add(tech)
                        self._logger.debug(f"Detected technology: {tech}")
                        break
                except re.error:
                    continue

        # Check for common frameworks by specific patterns
        if "csrfmiddlewaretoken" in html_lower:
            detected.add("django")
        if "flask-session" in html_lower or "flask.session" in html_lower:
            detected.add("flask")
        if "wp-content" in html_lower and "wp-includes" in html_lower:
            detected.add("wordpress")
        if "laravel-session" in html_lower:
            detected.add("laravel")
        if "authenticity_token" in html_lower:
            detected.add("rails")
        if "__VIEWSTATE" in html and "__EVENTVALIDATION" in html:
            detected.add("aspnet")

        self._logger.info(f"Detected technologies: {detected}")
        return list(detected)

    def extract_parameters(self, urls: list[str]) -> list[str]:
        """
        Extract unique parameters from a list of URLs.

        Args:
            urls: List of URLs to extract parameters from

        Returns:
            List of unique parameter names
        """
        self._logger.debug(f"Extracting parameters from {len(urls)} URLs")
        params: set[str] = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    params.update(query_params.keys())
            except (ValueError, TypeError) as e:
                self._logger.warning(f"Failed to parse URL: {url} - {e}")
                continue

        result = sorted(params)
        self._logger.debug(f"Extracted {len(result)} unique parameters")
        return result

    def _extract_parameters_from_url(self, url: str) -> list[str]:
        """
        Extract parameters from a single URL.

        Args:
            url: URL to extract parameters from

        Returns:
            List of parameter names

        Example:
            https://test.com?id=1&search=abc -> ["id", "search"]
        """
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                return sorted(params.keys())
        except (ValueError, TypeError) as e:
            self._logger.warning(f"Failed to extract parameters from URL: {e}")

        return []

    def extract_forms(self, html: str) -> list[FormInfo]:
        """
        Extract HTML forms from page content.

        Args:
            html: HTML content to analyze

        Returns:
            List of FormInfo objects
        """
        self._logger.debug("Extracting forms from HTML")
        forms: list[FormInfo] = []

        if not html:
            return forms

        # Simple regex-based form extraction
        # In production, use a proper HTML parser like BeautifulSoup
        form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        id_pattern = re.compile(r'id=["\']([^"\']*)["\']', re.IGNORECASE)
        name_pattern = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)

        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE
        )
        type_pattern = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)
        value_pattern = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
        required_pattern = re.compile(r"required", re.IGNORECASE)

        for match in form_pattern.finditer(html):
            form_html = match.group(1)

            # Extract form attributes
            action_match = action_pattern.search(match.group(0))
            method_match = method_pattern.search(match.group(0))
            id_match = id_pattern.search(match.group(0))
            name_match = name_pattern.search(match.group(0))

            form = FormInfo(
                action=action_match.group(1) if action_match else "",
                method=method_match.group(1).upper() if method_match else "GET",
                id=id_match.group(1) if id_match else "",
                name=name_match.group(1) if name_match else "",
            )

            # Extract input fields
            for input_match in input_pattern.finditer(form_html):
                field_name = input_match.group(1)
                field_html = input_match.group(0)

                type_match = type_pattern.search(field_html)
                value_match = value_pattern.search(field_html)
                required_match = required_pattern.search(field_html)

                field = FormField(
                    name=field_name,
                    type=type_match.group(1) if type_match else "text",
                    value=value_match.group(1) if value_match else "",
                    required=bool(required_match),
                )
                form.fields.append(field)

            if form.fields:  # Only add forms with fields
                forms.append(form)
                self._logger.debug(f"Found form with {len(form.fields)} fields")

        self._logger.info(f"Extracted {len(forms)} forms")
        return forms

    def choose_scanners(
        self,
        parameters: list[str],
        technologies: list[str],
        forms: list[FormInfo] | None = None,
    ) -> list[str]:
        """
        Choose appropriate scanners based on parameters and technologies.

        Args:
            parameters: List of parameter names
            technologies: List of detected technologies
            forms: Optional list of extracted forms

        Returns:
            List of recommended scanner names
        """
        self._logger.debug("Choosing scanners")
        forms = forms or []
        selected: set[str] = set()

        # Map parameters to scanners
        for param in parameters:
            param_lower = param.lower()
            for scanner, keywords in self.SCANNER_RULES.items():
                if any(keyword in param_lower for keyword in keywords):
                    selected.add(scanner)
                    self._logger.debug(
                        f"Parameter '{param}' suggests scanner: {scanner}"
                    )

        # Map technologies to scanners
        for tech in technologies:
            tech_lower = tech.lower()
            for detected_tech, scanners in self.TECH_SCANNER_MAP.items():
                if detected_tech in tech_lower:
                    for scanner in scanners:
                        selected.add(scanner)
                        self._logger.debug(
                            f"Technology '{tech}' suggests scanner: {scanner}"
                        )

        # Check forms for additional parameters
        for form in forms:
            for input_field in form.fields:
                field_lower = input_field.name.lower()
                for scanner, keywords in self.SCANNER_RULES.items():
                    if any(keyword in field_lower for keyword in keywords):
                        selected.add(scanner)
                        self._logger.debug(
                            f"Form field '{input_field.name}' suggests scanner: {scanner}"
                        )

        # Always include XSS for any forms (injections in forms)
        if forms:
            selected.add("xss")

        # Sort for consistent output
        result = sorted(selected)
        self._logger.info(f"Selected {len(result)} scanners: {result}")

        return result

    def _choose_scanners(
        self,
        parameters: list[str],
        technologies: list[str],
        forms: list[FormInfo] | None = None,
    ) -> list[str]:
        """
        Internal method to choose scanners (alias for choose_scanners).

        Args:
            parameters: List of parameter names
            technologies: List of detected technologies
            forms: Optional list of extracted forms

        Returns:
            List of recommended scanner names
        """
        return self.choose_scanners(parameters, technologies, forms)

    def get_analysis(self) -> TargetAnalysis | None:
        """
        Get the last analysis result.

        Returns:
            TargetAnalysis or None if no analysis has been performed
        """
        return self._analysis

    def get_recommended_scanners(self) -> list[str]:
        """
        Get recommended scanners from the last analysis.

        Returns:
            List of recommended scanner names or empty list
        """
        if self._analysis:
            return self._analysis.recommended_scanners.copy()
        return []

    def reset(self) -> None:
        """
        Reset the agent state.
        """
        self._target = None
        self._analysis = None
        self._logger.info("Agent reset")

    def analyze_full(
        self,
        url: str,
        html: str | None = None,
        urls: list[str] | None = None,
    ) -> TargetAnalysis:
        """
        Perform complete analysis with all available data.

        Args:
            url: Target URL
            html: Optional HTML content for technology/forms detection
            urls: Optional list of URLs for parameter extraction

        Returns:
            Complete TargetAnalysis
        """
        self._logger.info(f"Performing full analysis on: {url}")

        # Start with URL analysis
        analysis = self.analyze_target(url)

        # Detect technologies if HTML provided
        if html:
            technologies = self.detect_technologies(html)
            analysis.technologies = technologies

            # Extract forms from HTML
            forms = self.extract_forms(html)
            analysis.forms = forms

        # Extract parameters from multiple URLs if provided
        if urls:
            all_params = self.extract_parameters(urls)
            # Merge with existing parameters
            existing = set(analysis.parameters)
            existing.update(all_params)
            analysis.parameters = sorted(existing)

        # Update scanner recommendations with full data
        analysis.recommended_scanners = self._choose_scanners(
            parameters=analysis.parameters,
            technologies=analysis.technologies,
            forms=analysis.forms,
        )

        self._analysis = analysis
        self._logger.info(
            f"Full analysis complete: {len(analysis.parameters)} parameters, "
            f"{len(analysis.technologies)} technologies, "
            f"{len(analysis.forms)} forms, "
            f"{len(analysis.recommended_scanners)} recommended scanners"
        )

        return analysis
