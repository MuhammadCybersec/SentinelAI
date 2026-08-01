# =============================================================================
# FILE: tests/test_response_parser.py
# =============================================================================
# DESCRIPTION: Unit tests for ResponseParser - Complete Version
# =============================================================================

import os
import sys
import threading
from typing import Any

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.ai.response_parser import (
    AnalysisType,
    ConfidenceLevel,
    EmptyResponseError,
    InvalidJSONError,
    ParsedResponse,
    ResponseParser,
    ResponseParserError,
    SeverityLevel,
    VulnerabilityFinding,
)


@pytest.fixture
def parser() -> ResponseParser:
    return ResponseParser()


@pytest.fixture
def sample_sql_response() -> str:
    response = """
```json
{
    "sql_injection_findings": [
        {
            "title": "SQL Injection in Login Form",
            "description": "The login form is vulnerable to SQL injection",
            "severity": "high",
            "confidence": "high",
            "remediation": "Use parameterized queries",
            "cve_id": "CVE-2024-1234"
        }
    ],
    "summary": "Found 1 SQL injection vulnerability"
}
"""

    return response


@pytest.fixture
def sample_xss_response() -> str:
    response = """
{
    "xss_findings": [
        {
            "title": "Reflected XSS in Search",
            "description": "The search parameter is vulnerable to reflected XSS",
            "severity": "medium",
            "confidence": "high",
            "remediation": "Encode user input"
        }
    ],
    "summary": "Found 1 XSS vulnerability"
}
"""
    return response


@pytest.fixture
def sample_reverse_engineering_response() -> str:
    response = """
{
    "reverse_engineering_findings": [
        {
            "title": "Buffer Overflow in Function X",
            "description": "Function X is vulnerable to buffer overflow",
            "severity": "critical",
            "confidence": "medium"
        }
    ],
    "summary": "Found 1 reverse engineering issue"
}
"""
    return response


@pytest.fixture
def sample_malware_response() -> str:
    response = """
{
    "malware_analysis_findings": [
        {
            "title": "Suspicious Registry Key",
            "description": "Malware modifies registry to persist",
            "severity": "high",
            "confidence": "high"
        }
    ],
    "summary": "Found 1 malware indicator"
}
"""
    return response


@pytest.fixture
def sample_security_report_response() -> str:
    response = """
{
    "vulnerabilities": [
        {
            "title": "Security Misconfiguration",
            "description": "Server is misconfigured",
            "severity": "medium",
            "confidence": "high"
        }
    ],
    "summary": "Security report generated successfully"
}
"""
    return response


@pytest.fixture
def invalid_json_response() -> str:
    response = """
{
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "description": "Missing closing brace"
        }
    ]
"""
    return response


@pytest.fixture
def empty_response() -> str:
    return ""


@pytest.fixture
def sample_finding_data() -> dict[str, Any]:
    return {
        "title": "Test Finding",
        "description": "Test description",
        "severity": "high",
        "confidence": "high",
        "affected_component": "Test Component",
        "remediation": "Test remediation",
        "cve_id": "CVE-2024-1234",
        "references": ["https://example.com"],
    }


class TestVulnerabilityFinding:
    def test_finding_creation(self) -> None:
        finding = VulnerabilityFinding(
            title="SQL Injection",
            description="A SQL injection vulnerability exists",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            affected_component="Login Form",
            remediation="Use prepared statements",
            cve_id="CVE-2024-1234",
            references=["https://example.com"],
        )
        assert finding.title == "SQL Injection"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == ConfidenceLevel.HIGH
        assert finding.affected_component == "Login Form"

    def test_finding_to_dict(self) -> None:
        finding = VulnerabilityFinding(
            title="SQL Injection",
            description="A SQL injection vulnerability exists",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            affected_component="Login Form",
            remediation="Use prepared statements",
            cve_id="CVE-2024-1234",
            references=["https://example.com"],
        )
        data = finding.to_dict()
        assert data["title"] == "SQL Injection"
        assert data["severity"] == "high"
        assert data["confidence"] == "high"
        assert data["affected_component"] == "Login Form"

    def test_finding_defaults(self) -> None:
        finding = VulnerabilityFinding(
            title="SQL Injection",
            description="A SQL injection vulnerability exists",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
        )
        assert finding.affected_component is None
        assert finding.remediation is None
        assert finding.cve_id is None
        assert finding.references == []


class TestParsedResponse:
    def test_response_creation(self) -> None:
        response = ParsedResponse(
            analysis_type=AnalysisType.SQL_INJECTION,
            raw_text="Raw response",
            cleaned_text="Cleaned response",
            summary="Test summary",
            confidence=ConfidenceLevel.HIGH,
        )
        assert response.analysis_type == AnalysisType.SQL_INJECTION
        assert response.raw_text == "Raw response"
        assert response.cleaned_text == "Cleaned response"
        assert response.summary == "Test summary"
        assert response.confidence == ConfidenceLevel.HIGH

    def test_response_to_dict(self) -> None:
        response = ParsedResponse(
            analysis_type=AnalysisType.XSS,
            raw_text="Raw response",
            cleaned_text="Cleaned response",
            summary="Test summary",
            confidence=ConfidenceLevel.HIGH,
            metadata={"key": "value"},
        )
        data = response.to_dict()
        assert data["analysis_type"] == "xss"
        assert data["summary"] == "Test summary"
        assert data["confidence"] == "high"
        assert data["metadata"] == {"key": "value"}

    def test_response_get_summary(self) -> None:
        finding = VulnerabilityFinding(
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
        )
        response = ParsedResponse(
            analysis_type=AnalysisType.SQL_INJECTION,
            raw_text="Raw",
            cleaned_text="Cleaned",
            findings=[finding],
            confidence=ConfidenceLevel.HIGH,
        )
        summary = response.get_summary()
        assert "sql_injection" in summary
        assert "1 findings" in summary

    def test_response_with_json_data(self) -> None:
        json_data = {"key": "value", "number": 42}
        response = ParsedResponse(
            analysis_type=AnalysisType.GENERIC,
            raw_text='{"key": "value"}',
            cleaned_text='{"key": "value"}',
            json_data=json_data,
            is_json=True,
        )
        assert response.json_data == json_data
        assert response.is_json is True


class TestResponseParser:
    def test_initialization(self, parser: ResponseParser) -> None:
        assert parser is not None

    def test_parse_text_success(self, parser: ResponseParser) -> None:
        response = "This is a simple text response."
        parsed = parser.parse_text(response)
        assert parsed.analysis_type == AnalysisType.GENERIC
        assert parsed.raw_text == response
        assert "Text response parsed" in parsed.summary
        assert parsed.is_json is False

    def test_parse_text_empty(self, parser: ResponseParser) -> None:
        with pytest.raises(EmptyResponseError, match="Response is empty"):
            parser.parse_text("")

    def test_parse_text_whitespace(self, parser: ResponseParser) -> None:
        with pytest.raises(EmptyResponseError, match="Response is empty"):
            parser.parse_text("   \n   \t   ")

    def test_parse_json_success(self, parser: ResponseParser) -> None:
        json_str = '{"key": "value", "number": 42}'
        parsed = parser.parse_json(json_str)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert parsed.json_data["key"] == "value"
        assert parsed.json_data["number"] == 42

    def test_parse_json_with_markdown(self, parser: ResponseParser) -> None:
        response = '```json\n{"key": "value"}\n```'
        parsed = parser.parse_json(response)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert parsed.json_data["key"] == "value"

    def test_parse_json_empty(self, parser: ResponseParser) -> None:
        with pytest.raises(EmptyResponseError, match="Response is empty"):
            parser.parse_json("")

    def test_parse_json_invalid(self, parser: ResponseParser) -> None:
        with pytest.raises(InvalidJSONError, match="No valid JSON"):
            parser.parse_json("This is not JSON")

    def test_parse_json_array(self, parser: ResponseParser) -> None:
        json_str = '["item1", "item2", "item3"]'
        parsed = parser.parse_json(json_str)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert len(parsed.json_data) == 3
        assert parsed.json_data[0] == "item1"

    def test_parse_json_nested(self, parser: ResponseParser) -> None:
        json_str = '{"outer": {"inner": "value"}}'
        parsed = parser.parse_json(json_str)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert parsed.json_data["outer"]["inner"] == "value"

    def test_clean_code_fences(self, parser: ResponseParser) -> None:
        text = "```python\nprint('hello')\n```"
        cleaned = parser._remove_code_fences(text)
        assert "```" not in cleaned
        assert "print('hello')" in cleaned

    def test_clean_inline_code(self, parser: ResponseParser) -> None:
        text = "This is `inline code` text."
        cleaned = parser._remove_code_fences(text)
        assert "`" not in cleaned
        assert "inline code" in cleaned

    def test_normalize_whitespace(self, parser: ResponseParser) -> None:
        text = "This  has  multiple   spaces."
        normalized = parser._normalize_whitespace(text)
        assert normalized == "This has multiple spaces."

    def test_extract_json_from_markdown(self, parser: ResponseParser) -> None:
        text = '```json\n{"key": "value"}\n```'
        extracted = parser._extract_json_from_markdown(text)
        assert extracted is not None
        assert '"key": "value"' in extracted

    def test_extract_json_from_text(self, parser: ResponseParser) -> None:
        text = 'Here is some JSON: {"key": "value"} and more text.'
        extracted = parser._extract_json_from_text(text)
        assert extracted is not None
        assert '"key": "value"' in extracted

    def test_is_valid_json_true(self, parser: ResponseParser) -> None:
        assert parser._is_valid_json('{"key": "value"}') is True

    def test_is_valid_json_false(self, parser: ResponseParser) -> None:
        assert parser._is_valid_json('{"key": "value"') is False

    def test_parse_severity(self, parser: ResponseParser) -> None:
        assert parser._parse_severity("critical") == SeverityLevel.CRITICAL
        assert parser._parse_severity("high") == SeverityLevel.HIGH
        assert parser._parse_severity("medium") == SeverityLevel.MEDIUM
        assert parser._parse_severity("low") == SeverityLevel.LOW
        assert parser._parse_severity("info") == SeverityLevel.INFO
        assert parser._parse_severity("unknown") == SeverityLevel.MEDIUM
        assert parser._parse_severity(None) == SeverityLevel.MEDIUM

    def test_parse_confidence(self, parser: ResponseParser) -> None:
        assert parser._parse_confidence("high") == ConfidenceLevel.HIGH
        assert parser._parse_confidence("medium") == ConfidenceLevel.MEDIUM
        assert parser._parse_confidence("low") == ConfidenceLevel.LOW
        assert parser._parse_confidence(0.9) == ConfidenceLevel.HIGH
        assert parser._parse_confidence(0.6) == ConfidenceLevel.MEDIUM
        assert parser._parse_confidence(0.3) == ConfidenceLevel.LOW
        assert parser._parse_confidence(None) == ConfidenceLevel.UNKNOWN


class TestAnalysisParsing:
    def test_parse_sql_analysis(
        self, parser: ResponseParser, sample_sql_response: str
    ) -> None:
        parsed = parser.parse_sql_analysis(sample_sql_response)
        assert parsed.analysis_type == AnalysisType.SQL_INJECTION
        assert len(parsed.findings) >= 1
        assert parsed.findings[0].title == "SQL Injection in Login Form"
        assert parsed.findings[0].severity == SeverityLevel.HIGH
        assert parsed.findings[0].confidence == ConfidenceLevel.HIGH
        assert parsed.is_json is True

    def test_parse_sql_analysis_without_json(self, parser: ResponseParser) -> None:
        response = "SQL Injection Analysis: The query is vulnerable to SQL injection."
        parsed = parser.parse_sql_analysis(response)
        assert parsed.analysis_type == AnalysisType.SQL_INJECTION
        assert parsed.is_json is False

    def test_parse_sql_analysis_empty(self, parser: ResponseParser) -> None:
        with pytest.raises(EmptyResponseError, match="Response is empty"):
            parser.parse_sql_analysis("")

    def test_parse_xss_analysis(
        self, parser: ResponseParser, sample_xss_response: str
    ) -> None:
        parsed = parser.parse_xss_analysis(sample_xss_response)
        assert parsed.analysis_type == AnalysisType.XSS
        assert len(parsed.findings) >= 1
        assert parsed.findings[0].title == "Reflected XSS in Search"
        assert parsed.findings[0].severity == SeverityLevel.MEDIUM
        assert parsed.findings[0].confidence == ConfidenceLevel.HIGH
        assert parsed.is_json is True

    def test_parse_xss_analysis_without_json(self, parser: ResponseParser) -> None:
        response = "XSS Analysis: The search parameter is vulnerable to XSS."
        parsed = parser.parse_xss_analysis(response)
        assert parsed.analysis_type == AnalysisType.XSS
        assert parsed.is_json is False

    def test_parse_reverse_engineering(
        self, parser: ResponseParser, sample_reverse_engineering_response: str
    ) -> None:
        parsed = parser.parse_reverse_engineering(sample_reverse_engineering_response)
        assert parsed.analysis_type == AnalysisType.REVERSE_ENGINEERING
        assert len(parsed.findings) >= 1
        assert parsed.findings[0].severity == SeverityLevel.CRITICAL
        assert parsed.findings[0].confidence == ConfidenceLevel.MEDIUM
        assert parsed.is_json is True

    def test_parse_malware_analysis(
        self, parser: ResponseParser, sample_malware_response: str
    ) -> None:
        parsed = parser.parse_malware_analysis(sample_malware_response)
        assert parsed.analysis_type == AnalysisType.MALWARE_ANALYSIS
        assert len(parsed.findings) >= 1
        assert parsed.findings[0].confidence == ConfidenceLevel.HIGH
        assert parsed.is_json is True

    def test_parse_security_report(
        self, parser: ResponseParser, sample_security_report_response: str
    ) -> None:
        parsed = parser.parse_security_report(sample_security_report_response)
        assert parsed.analysis_type == AnalysisType.SECURITY_REPORT
        assert len(parsed.findings) >= 1
        assert parsed.is_json is True

    def test_parse_security_report_without_json(self, parser: ResponseParser) -> None:
        response = "Security Report: No vulnerabilities found."
        parsed = parser.parse_security_report(response)
        assert parsed.analysis_type == AnalysisType.SECURITY_REPORT
        assert parsed.is_json is False

    def test_parse_vulnerability_explanation(self, parser: ResponseParser) -> None:
        response = """Vulnerability: SQL Injection
Severity: High
Description: The application is vulnerable to SQL injection."""
        parsed = parser.parse_vulnerability_explanation(response)
        assert parsed.analysis_type == AnalysisType.VULNERABILITY_EXPLANATION
        assert parsed.findings == []

    def test_parse_vulnerability_explanation_with_json(
        self, parser: ResponseParser
    ) -> None:
        response = """
```json
{
    "vulnerability": "SQL Injection",
    "severity": "high",
    "description": "SQL injection vulnerability"
}
```
"""
        parsed = parser.parse_vulnerability_explanation(response)
        assert parsed.analysis_type == AnalysisType.VULNERABILITY_EXPLANATION
        assert parsed.is_json is False
        assert len(parsed.findings) == 0


class TestFindingsExtraction:
    def test_extract_findings_from_json(self, parser: ResponseParser) -> None:
        json_data = {
            "vulnerabilities": [
                {
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability",
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        }
        findings = parser._extract_findings_from_json(json_data, "sql_injection")
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == SeverityLevel.HIGH

    def test_extract_findings_from_json_with_findings_field(
        self, parser: ResponseParser
    ) -> None:
        json_data = {
            "findings": [
                {
                    "title": "XSS Vulnerability",
                    "description": "XSS vulnerability",
                    "severity": "medium",
                    "confidence": "high",
                }
            ]
        }
        findings = parser._extract_findings_from_json(json_data, "xss")
        assert len(findings) == 1
        assert findings[0].title == "XSS Vulnerability"

    def test_extract_findings_from_json_with_results_field(
        self, parser: ResponseParser
    ) -> None:
        json_data = {
            "results": [
                {
                    "title": "Buffer Overflow",
                    "description": "Buffer overflow vulnerability",
                    "severity": "critical",
                    "confidence": "medium",
                }
            ]
        }
        findings = parser._extract_findings_from_json(json_data, "reverse_engineering")
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_extract_findings_from_json_with_issues_field(
        self, parser: ResponseParser
    ) -> None:
        json_data = {
            "issues": [
                {
                    "title": "Malware Detection",
                    "description": "Malware detected",
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        }
        findings = parser._extract_findings_from_json(json_data, "malware_analysis")
        assert len(findings) == 1
        assert findings[0].title == "Malware Detection"

    def test_extract_findings_from_json_empty(self, parser: ResponseParser) -> None:
        json_data = {}
        findings = parser._extract_findings_from_json(json_data, "generic")
        assert findings == []

    def test_extract_findings_from_text(self, parser: ResponseParser) -> None:
        text = (
            "Finding 1: SQL Injection\nSeverity: High\nThe application is vulnerable."
        )
        findings = parser._extract_findings_from_text(text, AnalysisType.SQL_INJECTION)
        assert len(findings) >= 1

    def test_extract_findings_from_text_empty(self, parser: ResponseParser) -> None:
        findings = parser._extract_findings_from_text("", AnalysisType.GENERIC)
        assert findings == []


class TestSummaryAndConfidenceExtraction:
    def test_extract_summary_from_json(self, parser: ResponseParser) -> None:
        json_data = {"summary": "This is the summary"}
        summary = parser._extract_summary_from_json(json_data)
        assert summary == "This is the summary"

    def test_extract_summary_from_json_empty(self, parser: ResponseParser) -> None:
        json_data = {}
        summary = parser._extract_summary_from_json(json_data)
        assert summary == "Analysis completed successfully"

    def test_extract_summary_from_text(self, parser: ResponseParser) -> None:
        text = "Summary:\nThis is the summary."
        summary = parser._extract_summary_from_text(text)
        assert summary == "This is the summary."

    def test_extract_summary_from_text_no_summary(self, parser: ResponseParser) -> None:
        text = "This is just plain text."
        summary = parser._extract_summary_from_text(text)
        assert summary == "This is just plain text."

    def test_extract_confidence_from_json(self, parser: ResponseParser) -> None:
        json_data = {"confidence": "high"}
        confidence = parser._extract_confidence_from_json(json_data)
        assert confidence == ConfidenceLevel.HIGH

    def test_extract_confidence_from_json_empty(self, parser: ResponseParser) -> None:
        json_data = {}
        confidence = parser._extract_confidence_from_json(json_data)
        assert confidence == ConfidenceLevel.MEDIUM

    def test_extract_confidence_from_text_high(self, parser: ResponseParser) -> None:
        text = "We are clearly confident this is a vulnerability."
        confidence = parser._extract_confidence_from_text(text)
        assert confidence == ConfidenceLevel.HIGH

    def test_extract_confidence_from_text_medium(self, parser: ResponseParser) -> None:
        text = "This is likely a vulnerability."
        confidence = parser._extract_confidence_from_text(text)
        assert confidence == ConfidenceLevel.MEDIUM

    def test_extract_confidence_from_text_low(self, parser: ResponseParser) -> None:
        text = "This is maybe a vulnerability."
        confidence = parser._extract_confidence_from_text(text)
        assert confidence == ConfidenceLevel.LOW

    def test_extract_confidence_from_text_unknown(self, parser: ResponseParser) -> None:
        text = "This is some text without confidence indicators."
        confidence = parser._extract_confidence_from_text(text)
        assert confidence == ConfidenceLevel.UNKNOWN


class TestCreateFindingFromDict:
    def test_create_finding_from_dict_full(self, parser: ResponseParser) -> None:
        data = {
            "title": "Test Finding",
            "description": "Test description",
            "severity": "high",
            "confidence": "high",
            "affected_component": "Test Component",
            "remediation": "Test remediation",
            "cve_id": "CVE-2024-1234",
            "references": ["https://example.com"],
        }
        finding = parser._create_finding_from_dict(data)
        assert finding is not None
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == ConfidenceLevel.HIGH
        assert finding.affected_component == "Test Component"
        assert finding.remediation == "Test remediation"
        assert finding.cve_id == "CVE-2024-1234"
        assert finding.references == ["https://example.com"]

    def test_create_finding_from_dict_minimal(self, parser: ResponseParser) -> None:
        data = {"title": "Test", "description": "Test description"}
        finding = parser._create_finding_from_dict(data)
        assert finding is not None
        assert finding.title == "Test"
        assert finding.severity == SeverityLevel.MEDIUM
        assert finding.confidence == ConfidenceLevel.MEDIUM

    def test_create_finding_from_dict_missing_title(
        self, parser: ResponseParser
    ) -> None:
        data = {"description": "Test description"}
        finding = parser._create_finding_from_dict(data)
        assert finding is None

    def test_create_finding_from_dict_missing_description(
        self, parser: ResponseParser
    ) -> None:
        data = {"title": "Test"}
        finding = parser._create_finding_from_dict(data)
        assert finding is None


class TestEdgeCases:
    def test_extract_json_from_text_nested(self, parser: ResponseParser) -> None:
        text = '{"outer": {"inner": "value"}}'
        extracted = parser._extract_json_from_text(text)
        assert extracted is not None

    def test_parse_json_with_multiple_code_fences(self, parser: ResponseParser) -> None:
        text = '```json\n{"key1": "value1"}\n```\n```json\n{"key2": "value2"}\n```'
        parsed = parser.parse_json(text)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert parsed.json_data["key1"] == "value1"

    def test_parse_json_with_whitespace(self, parser: ResponseParser) -> None:
        text = ' \n {"key": "value"} \n '
        parsed = parser.parse_json(text)
        assert parsed.is_json is True
        assert parsed.json_data is not None
        assert parsed.json_data["key"] == "value"


class TestThreadSafety:
    def test_concurrent_parsing(self, parser: ResponseParser) -> None:
        results: list[ParsedResponse] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def parse_response(index: int) -> None:
            try:
                json_str = f'{{"id": {index}, "value": "test_{index}"}}'
                result = parser.parse_json(json_str)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = []
        for i in range(10):
            thread = threading.Thread(target=parse_response, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert len(results) == 10

    def test_concurrent_complex_parsing(self, parser: ResponseParser) -> None:
        responses = [
            '{"vulnerabilities": [{"title": "SQLi", "description": "SQL injection", "severity": "high"}]}',
            '{"findings": [{"name": "XSS", "details": "Cross-site scripting", "risk_level": "medium"}]}',
            '{"issues": [{"issue": "Buffer Overflow", "details": "Overflow", "severity": "critical"}]}',
        ]
        errors: list[Exception] = []
        lock = threading.Lock()

        def parse_analysis(index: int) -> None:
            try:
                response = responses[index % len(responses)]
                parser.parse_sql_analysis(response)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = []
        for i in range(15):
            thread = threading.Thread(target=parse_analysis, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert errors == []


class TestExceptions:
    def test_response_parser_error_base(self) -> None:
        error = ResponseParserError("Test error")
        assert str(error) == "Test error"

    def test_empty_response_error(self) -> None:
        error = EmptyResponseError("Response is empty")
        assert "Response is empty" in str(error)

    def test_invalid_json_error(self) -> None:
        error = InvalidJSONError("Invalid JSON")
        assert "Invalid JSON" in str(error)


class TestIntegration:
    def test_full_workflow_json(self, parser: ResponseParser) -> None:
        response = """
```json
{
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "description": "SQL injection in login",
            "severity": "high",
            "confidence": "high",
            "remediation": "Use parameterized queries"
        }
    ],
    "summary": "Found 1 vulnerability"
}
```
"""
        parsed = parser.parse_sql_analysis(response)
        assert parsed.analysis_type == AnalysisType.SQL_INJECTION
        assert len(parsed.findings) == 1
        assert parsed.findings[0].title == "SQL Injection"
        assert parsed.findings[0].severity == SeverityLevel.HIGH
        assert parsed.findings[0].confidence == ConfidenceLevel.HIGH
        assert parsed.is_json is True

    def test_full_workflow_text(self, parser: ResponseParser) -> None:
        response = """
Vulnerability Analysis:
Finding 1: SQL Injection
Severity: High
Description: The application is vulnerable to SQL injection.
"""
        parsed = parser.parse_sql_analysis(response)
        assert parsed.analysis_type == AnalysisType.SQL_INJECTION
        assert parsed.findings is not None
        assert parsed.is_json is False

    def test_full_workflow_mixed(self, parser: ResponseParser) -> None:
        response = """
Here is the analysis:

```json
{
    "findings": [
        {
            "title": "XSS Vulnerability",
            "description": "Reflected XSS in search",
            "severity": "medium"
        }
    ]
}
```
"""
        parsed = parser.parse_xss_analysis(response)
        assert parsed.analysis_type == AnalysisType.XSS
        assert parsed.is_json is True

    def test_full_workflow_multiple_findings(self, parser: ResponseParser) -> None:
        response = """
```json
{
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "description": "SQL injection vulnerability",
            "severity": "critical",
            "confidence": "high"
        },
        {
            "title": "XSS",
            "description": "Cross-site scripting vulnerability",
            "severity": "medium",
            "confidence": "medium"
        }
    ],
    "summary": "Found 2 vulnerabilities"
}
```
"""
        parsed = parser.parse_sql_analysis(response)
        assert len(parsed.findings) == 2
        assert parsed.findings[0].severity == SeverityLevel.CRITICAL
        assert parsed.findings[1].severity == SeverityLevel.MEDIUM


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
