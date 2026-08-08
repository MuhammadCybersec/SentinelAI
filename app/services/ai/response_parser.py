# =============================================================================
# FILE: app/services/ai/response_parser.py
# =============================================================================
# DESCRIPTION:
# Response Parser Service for SentinelAI.
#
# This module provides a production-ready response parser that extracts
# structured data from AI model responses. It handles various response
# formats including JSON, markdown, and plain text.
#
# DESIGN PRINCIPLES:
# - SOLID: Single Responsibility (only parses responses)
# - Clean Architecture: Independent of AI providers
# - Thread Safety: Stateless parsing methods
# - Provider Independent: No external dependencies
#
# USAGE:
#     parser = ResponseParser()
#     response = '''```json
#     {
#         "vulnerabilities": [
#             {"title": "SQL Injection", "severity": "high"}
#         ]
#     }
#     ```'''
#     parsed = parser.parse_sql_analysis(response)
#     print(parsed.findings[0].title)  # "SQL Injection"
# =============================================================================


import json
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
)

# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class ResponseParserError(Exception):
    """Base exception for response parser errors."""


class EmptyResponseError(ResponseParserError):
    """Raised when the response is empty."""


class InvalidJSONError(ResponseParserError):
    """Raised when the response contains invalid JSON."""


class MalformedResponseError(ResponseParserError):
    """Raised when the response is malformed."""


class MissingFieldError(ResponseParserError):
    """Raised when a required field is missing."""


class InvalidFieldTypeError(ResponseParserError):
    """Raised when a field has an invalid type."""


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================


class AnalysisType(Enum):
    """Types of analysis that can be parsed."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    REVERSE_ENGINEERING = "reverse_engineering"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY_EXPLANATION = "vulnerability_explanation"
    SECURITY_REPORT = "security_report"
    GENERIC = "generic"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(Enum):
    """Confidence levels for analysis results."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# =============================================================================
# DATACLASSES
# =============================================================================


@dataclass(slots=True, frozen=True)
class VulnerabilityFinding:
    """
    A single vulnerability finding.

    Attributes:
        title: Short title of the finding
        description: Detailed description
        severity: Severity level
        confidence: Confidence level
        affected_component: Component affected (optional)
        remediation: Recommended remediation (optional)
        cve_id: CVE ID if applicable (optional)
        references: List of references (optional)
    """

    title: str
    description: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    affected_component: str | None = None
    remediation: str | None = None
    cve_id: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "references": self.references,
        }


@dataclass(slots=True, frozen=True)
class ParsedResponse:
    """
    Structured parsed response from AI model.

    Attributes:
        analysis_type: Type of analysis performed
        raw_text: Original raw response text
        cleaned_text: Cleaned text without markdown
        json_data: Parsed JSON data if available
        findings: List of vulnerability findings
        summary: Summary of the analysis
        confidence: Overall confidence level
        metadata: Additional metadata
        parsed_at: Timestamp of parsing
        is_json: Whether the response was parsed as JSON
    """

    analysis_type: AnalysisType
    raw_text: str
    cleaned_text: str
    json_data: dict[str, Any] | None = None
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    summary: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)
    parsed_at: float = field(default_factory=time.time)
    is_json: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "analysis_type": self.analysis_type.value,
            "raw_text": self.raw_text[:1000],  # Truncate for safety
            "cleaned_text": self.cleaned_text[:1000],
            "json_data": self.json_data,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "confidence": self.confidence.value,
            "metadata": self.metadata,
            "parsed_at": self.parsed_at,
            "is_json": self.is_json,
        }

    def get_summary(self) -> str:
        """Get a human-readable summary."""
        return f"{self.analysis_type.value}: {len(self.findings)} findings, confidence: {self.confidence.value}"


# =============================================================================
# RESPONSE PARSER CLASS
# =============================================================================


class ResponseParser:
    """
    Thread-safe response parser for AI model responses.

    This class is responsible only for parsing responses. It does not
    communicate with any AI provider.

    Features:
        - JSON extraction and validation
        - Markdown code fence removal
        - Whitespace normalization
        - Structured parsing for various analysis types
        - Provider independent

    Example:
        >>> parser = ResponseParser()
        >>> response = '''```json
        ... {
        ...     "vulnerabilities": [
        ...         {"title": "SQL Injection", "severity": "high"}
        ...     ]
        ... }
        ... ```'''
        >>> parsed = parser.parse_sql_analysis(response)
        >>> print(parsed.findings[0].title)
        SQL Injection
    """

    # Regex patterns for markdown code fences
    _CODE_FENCE_PATTERN = re.compile(
        r"```(?:json|javascript|js|python|text)?\s*\n?(.*?)\n?```",
        re.DOTALL | re.IGNORECASE,
    )
    _SIMPLE_CODE_FENCE_PATTERN = re.compile(r"```([^`]*)```", re.DOTALL)
    _INLINE_CODE_PATTERN = re.compile(r"`([^`]+)`")

    # Regex for cleaning whitespace
    _WHITESPACE_PATTERN = re.compile(r"\s+")
    _LEADING_TRAILING_WHITESPACE = re.compile(r"^\s+|\s+$")

    # Regex for extracting JSON from text
    _JSON_OBJECT_PATTERN = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}")
    _JSON_ARRAY_PATTERN = re.compile(r"\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]")

    def __init__(self) -> None:
        """Initialize the ResponseParser."""
        self._lock = threading.RLock()

    # =========================================================================
    # PUBLIC METHODS
    # =========================================================================

    def parse_text(self, response: str) -> ParsedResponse:
        """
        Parse raw text response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response

        Raises:
            EmptyResponseError: If response is empty
        """
        if not response or not response.strip():
            raise EmptyResponseError("Response is empty or contains only whitespace")

        cleaned = self._clean_text(response)

        return ParsedResponse(
            analysis_type=AnalysisType.GENERIC,
            raw_text=response,
            cleaned_text=cleaned,
            summary="Text response parsed successfully",
        )

    def parse_json(self, response: str) -> ParsedResponse:
        """
        Parse JSON response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response

        Raises:
            EmptyResponseError: If response is empty
            InvalidJSONError: If response contains invalid JSON
        """
        if not response or not response.strip():
            raise EmptyResponseError("Response is empty or contains only whitespace")

        # Try to extract JSON from markdown
        json_str = self._extract_json_from_markdown(response)

        # If no JSON found, try to parse the entire response
        if json_str is None:
            json_str = self._extract_json_from_text(response)

        if json_str is None:
            raise InvalidJSONError("No valid JSON found in response")

        try:
            json_data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise InvalidJSONError(f"Invalid JSON response: {e}")

        cleaned = self._clean_text(response)

        return ParsedResponse(
            analysis_type=AnalysisType.GENERIC,
            raw_text=response,
            cleaned_text=cleaned,
            json_data=json_data,
            summary="JSON response parsed successfully",
            is_json=True,
        )

    def parse_sql_analysis(self, response: str) -> ParsedResponse:
        """
        Parse SQL injection analysis response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.SQL_INJECTION,
            "sql_injection",
        )

    def parse_xss_analysis(self, response: str) -> ParsedResponse:
        """
        Parse XSS analysis response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.XSS,
            "xss",
        )

    def parse_reverse_engineering(self, response: str) -> ParsedResponse:
        """
        Parse reverse engineering analysis response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.REVERSE_ENGINEERING,
            "reverse_engineering",
        )

    def parse_malware_analysis(self, response: str) -> ParsedResponse:
        """
        Parse malware analysis response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.MALWARE_ANALYSIS,
            "malware_analysis",
        )

    def parse_vulnerability_explanation(self, response: str) -> ParsedResponse:
        """
        Parse vulnerability explanation response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.VULNERABILITY_EXPLANATION,
            "vulnerability_explanation",
        )

    def parse_security_report(self, response: str) -> ParsedResponse:
        """
        Parse security report response.

        Args:
            response: Raw response text

        Returns:
            ParsedResponse: Structured parsed response with findings

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        return self._parse_analysis_response(
            response,
            AnalysisType.SECURITY_REPORT,
            "security_report",
        )

    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================

    def _clean_text(self, text: str) -> str:
        """
        Clean text by removing markdown and normalizing whitespace.

        Args:
            text: Raw text to clean

        Returns:
            Cleaned text
        """
        # Remove code fences
        text = self._remove_code_fences(text)

        # Normalize whitespace
        text = self._normalize_whitespace(text)

        return text

    def _remove_code_fences(self, text: str) -> str:
        """
        Remove markdown code fences from text.

        Args:
            text: Text containing code fences

        Returns:
            Text with code fences removed
        """
        # Remove code blocks with language specifiers
        text = self._CODE_FENCE_PATTERN.sub(r"\1", text)

        # Remove simple code fences
        text = self._SIMPLE_CODE_FENCE_PATTERN.sub(r"\1", text)

        # Remove inline code (keep content)
        text = self._INLINE_CODE_PATTERN.sub(r"\1", text)

        return text

    def _normalize_whitespace(self, text: str) -> str:
        """
        Normalize whitespace in text.

        Args:
            text: Text to normalize

        Returns:
            Normalized text
        """
        # Replace multiple whitespace with single space
        text = self._WHITESPACE_PATTERN.sub(" ", text)

        # Remove leading/trailing whitespace
        text = self._LEADING_TRAILING_WHITESPACE.sub("", text)

        return text

    def _extract_json_from_markdown(self, text: str) -> str | None:
        """
        Extract JSON from markdown code fences.

        Args:
            text: Text containing markdown

        Returns:
            Extracted JSON string or None
        """
        # Look for JSON in code fences
        for match in self._CODE_FENCE_PATTERN.finditer(text):
            potential_json = match.group(1).strip()
            if self._is_valid_json(potential_json):
                return potential_json

        # Look for simple code fence
        for match in self._SIMPLE_CODE_FENCE_PATTERN.finditer(text):
            potential_json = match.group(1).strip()
            if self._is_valid_json(potential_json):
                return potential_json

        return None

    def _extract_json_from_text(self, text: str) -> str | None:
        """
        Extract JSON from plain text.

        Args:
            text: Text containing JSON

        Returns:
            Extracted JSON string or None
        """
        # Try to find JSON object
        for match in self._JSON_OBJECT_PATTERN.finditer(text):
            potential_json = match.group(0).strip()
            if self._is_valid_json(potential_json):
                return potential_json

        # Try to find JSON array
        for match in self._JSON_ARRAY_PATTERN.finditer(text):
            potential_json = match.group(0).strip()
            if self._is_valid_json(potential_json):
                return potential_json

        return None

    def _is_valid_json(self, text: str) -> bool:
        """
        Check if text is valid JSON.

        Args:
            text: Text to check

        Returns:
            True if text is valid JSON
        """
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False

    def _parse_analysis_response(
        self,
        response: str,
        analysis_type: AnalysisType,
        expected_type: str,
    ) -> ParsedResponse:
        """
        Parse an analysis response.

        Args:
            response: Raw response text
            analysis_type: Type of analysis
            expected_type: Expected JSON field for type

        Returns:
            ParsedResponse: Structured parsed response

        Raises:
            EmptyResponseError: If response is empty
            MalformedResponseError: If response is malformed
        """
        if not response or not response.strip():
            raise EmptyResponseError("Response is empty or contains only whitespace")

        cleaned = self._clean_text(response)

        # Try to parse as JSON first
        try:
            parsed = self.parse_json(response)
            if parsed.json_data:
                # Extract findings from JSON
                findings = self._extract_findings_from_json(
                    parsed.json_data,
                    expected_type,
                )
                if findings:
                    return ParsedResponse(
                        analysis_type=analysis_type,
                        raw_text=response,
                        cleaned_text=cleaned,
                        json_data=parsed.json_data,
                        findings=findings,
                        summary=self._extract_summary_from_json(parsed.json_data),
                        confidence=self._extract_confidence_from_json(parsed.json_data),
                        is_json=True,
                    )
        except (InvalidJSONError, EmptyResponseError):
            # Fall back to text parsing
            pass

        # Parse from text
        findings = self._extract_findings_from_text(cleaned, analysis_type)
        summary = self._extract_summary_from_text(cleaned)
        confidence = self._extract_confidence_from_text(cleaned)

        return ParsedResponse(
            analysis_type=analysis_type,
            raw_text=response,
            cleaned_text=cleaned,
            findings=findings,
            summary=summary,
            confidence=confidence,
        )

    def _extract_findings_from_json(
        self,
        json_data: dict[str, Any],
        expected_type: str,
    ) -> list[VulnerabilityFinding]:
        """
        Extract findings from JSON data.

        Args:
            json_data: Parsed JSON data
            expected_type: Expected type field name

        Returns:
            List of VulnerabilityFinding objects
        """
        findings = []

        # Check for findings in various common formats
        finding_sources = []

        # Check for 'vulnerabilities' field
        if "vulnerabilities" in json_data and isinstance(
            json_data["vulnerabilities"], list
        ):
            finding_sources.extend(json_data["vulnerabilities"])

        # Check for 'findings' field
        if "findings" in json_data and isinstance(json_data["findings"], list):
            finding_sources.extend(json_data["findings"])

        # Check for type-specific field
        type_key = f"{expected_type}_findings"
        if type_key in json_data and isinstance(json_data[type_key], list):
            finding_sources.extend(json_data[type_key])

        # Check for 'results' field
        if "results" in json_data and isinstance(json_data["results"], list):
            finding_sources.extend(json_data["results"])

        # Check for 'issues' field
        if "issues" in json_data and isinstance(json_data["issues"], list):
            finding_sources.extend(json_data["issues"])

        # Process each finding source
        for source in finding_sources:
            if not isinstance(source, dict):
                continue

            try:
                finding = self._create_finding_from_dict(source)
                if finding:
                    findings.append(finding)
            except (KeyError, ValueError):
                continue

        return findings

    def _create_finding_from_dict(
        self, data: dict[str, Any]
    ) -> VulnerabilityFinding | None:
        """
        Create a VulnerabilityFinding from a dictionary.

        Args:
            data: Dictionary containing finding data

        Returns:
            VulnerabilityFinding or None if invalid
        """
        # Required fields
        title = data.get("title") or data.get("name") or data.get("issue")
        description = (
            data.get("description") or data.get("details") or data.get("summary")
        )

        if not title or not description:
            return None

        # Severity
        severity_str = data.get("severity") or data.get("risk_level") or "medium"
        severity = self._parse_severity(severity_str)

        # Confidence
        confidence_str = data.get("confidence") or data.get("certainty") or "medium"
        confidence = self._parse_confidence(confidence_str)

        return VulnerabilityFinding(
            title=str(title),
            description=str(description),
            severity=severity,
            confidence=confidence,
            affected_component=data.get("affected_component") or data.get("component"),
            remediation=data.get("remediation")
            or data.get("fix")
            or data.get("recommendation"),
            cve_id=data.get("cve_id") or data.get("cve"),
            references=data.get("references") or data.get("refs") or [],
        )

    def _extract_findings_from_text(
        self,
        text: str,
        analysis_type: AnalysisType,
    ) -> list[VulnerabilityFinding]:
        """
        Extract findings from plain text.

        Args:
            text: Cleaned text
            analysis_type: Type of analysis

        Returns:
            List of VulnerabilityFinding objects
        """
        findings = []
        lines = text.split("\n")
        current_finding = None
        current_description = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for finding indicators
            finding_match = re.match(
                r"^(?:Finding|Issue|Vulnerability|Risk|\d+\.?)\s*[:]?\s*(.+)",
                line,
                re.IGNORECASE,
            )
            if finding_match:
                # Save previous finding
                if current_finding and current_description:
                    findings.append(
                        VulnerabilityFinding(
                            title=current_finding,
                            description=" ".join(current_description)[:500],
                            severity=SeverityLevel.MEDIUM,
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )
                current_finding = finding_match.group(1).strip()
                current_description = []
                continue

            # Look for severity indicators
            severity_match = re.search(
                r"(?:severity|risk level|priority)\s*[:]?\s*(critical|high|medium|low|info)",
                line,
                re.IGNORECASE,
            )
            if severity_match and current_finding:
                # The current finding already has severity info
                pass

            # Add to description
            if current_finding:
                current_description.append(line)

        # Add last finding
        if current_finding and current_description:
            findings.append(
                VulnerabilityFinding(
                    title=current_finding,
                    description=" ".join(current_description)[:500],
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )

        return findings

    def _extract_summary_from_json(self, json_data: dict[str, Any]) -> str:
        """
        Extract summary from JSON data.

        Args:
            json_data: Parsed JSON data

        Returns:
            Summary string
        """
        for key in ["summary", "overview", "executive_summary", "conclusion"]:
            if json_data.get(key):
                return str(json_data[key])

        # Use first finding's description as summary if available
        if json_data.get("vulnerabilities"):
            first = json_data["vulnerabilities"][0]
            if isinstance(first, dict) and "description" in first:
                return str(first["description"])[:200]

        return "Analysis completed successfully"

    def _extract_confidence_from_json(
        self, json_data: dict[str, Any]
    ) -> ConfidenceLevel:
        """
        Extract confidence level from JSON data.

        Args:
            json_data: Parsed JSON data

        Returns:
            ConfidenceLevel
        """
        for key in ["confidence", "overall_confidence", "certainty"]:
            if key in json_data:
                return self._parse_confidence(json_data[key])

        return ConfidenceLevel.MEDIUM

    def _extract_summary_from_text(self, text: str) -> str:
        """
        Extract summary from plain text.

        Args:
            text: Cleaned text

        Returns:
            Summary string
        """
        lines = text.split("\n")

        # Look for summary section
        for i, line in enumerate(lines):
            if re.search(
                r"(?:summary|overview|conclusion)\s*[:]?\s*", line, re.IGNORECASE
            ) and i + 1 < len(lines):
                return lines[i + 1].strip()

        # Take first non-empty line as summary
        for line in lines:
            if line.strip():
                return line.strip()[:200]

        return ""

    def _extract_confidence_from_text(self, text: str) -> ConfidenceLevel:
        """
        Extract confidence level from plain text.

        Args:
            text: Cleaned text

        Returns:
            ConfidenceLevel
        """
        # Look for confidence indicators
        if re.search(r"confidence\s*[:]?\s*high", text, re.IGNORECASE):
            return ConfidenceLevel.HIGH
        elif re.search(r"confidence\s*[:]?\s*medium", text, re.IGNORECASE):
            return ConfidenceLevel.MEDIUM
        elif re.search(r"confidence\s*[:]?\s*low", text, re.IGNORECASE):
            return ConfidenceLevel.LOW

        # Look for certainty indicators
        if re.search(r"(?:certain|definite|clearly)", text, re.IGNORECASE):
            return ConfidenceLevel.HIGH
        elif re.search(r"(?:likely|probably|indicates)", text, re.IGNORECASE):
            return ConfidenceLevel.MEDIUM
        elif re.search(r"(?:possible|maybe|uncertain)", text, re.IGNORECASE):
            return ConfidenceLevel.LOW

        return ConfidenceLevel.UNKNOWN

    def _parse_severity(self, value: Any) -> SeverityLevel:
        """
        Parse severity from various formats.

        Args:
            value: Severity value

        Returns:
            SeverityLevel
        """
        if not value:
            return SeverityLevel.MEDIUM

        if isinstance(value, SeverityLevel):
            return value

        value_str = str(value).lower().strip()

        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO,
            "moderate": SeverityLevel.MEDIUM,
            "severe": SeverityLevel.HIGH,
            "urgent": SeverityLevel.CRITICAL,
        }

        # Try exact match
        if value_str in severity_map:
            return severity_map[value_str]

        # Try partial match
        for key, level in severity_map.items():
            if key in value_str:
                return level

        return SeverityLevel.MEDIUM

    def _parse_confidence(self, value: Any) -> ConfidenceLevel:
        """
        Parse confidence from various formats.

        Args:
            value: Confidence value

        Returns:
            ConfidenceLevel
        """
        if not value:
            return ConfidenceLevel.UNKNOWN

        if isinstance(value, ConfidenceLevel):
            return value

        value_str = str(value).lower().strip()

        # Try numeric confidence (0-1 or 0-100)
        try:
            num_value = float(value_str)
            if num_value >= 0.8:
                return ConfidenceLevel.HIGH
            elif num_value >= 0.5:
                return ConfidenceLevel.MEDIUM
            elif num_value > 0:
                return ConfidenceLevel.LOW
        except ValueError:
            pass

        # Try string confidence
        confidence_map = {
            "high": ConfidenceLevel.HIGH,
            "medium": ConfidenceLevel.MEDIUM,
            "low": ConfidenceLevel.LOW,
            "unknown": ConfidenceLevel.UNKNOWN,
            "certain": ConfidenceLevel.HIGH,
            "likely": ConfidenceLevel.MEDIUM,
            "possible": ConfidenceLevel.LOW,
            "unclear": ConfidenceLevel.UNKNOWN,
        }

        for key, level in confidence_map.items():
            if key in value_str:
                return level

        return ConfidenceLevel.UNKNOWN
