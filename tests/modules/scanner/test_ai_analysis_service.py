"""
Unit tests for AIAnalysisService.
"""

import os
import sys
import threading
from unittest.mock import Mock

import pytest

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ),
)

from app.modules.scanner.exceptions.ai_analysis_exceptions import (
    ScannerAIAnalysisError,
    ScannerAIConnectionError,
    ScannerAINotConfiguredError,
    ScannerAIParsingError,
    ScannerAIReportError,
)
from app.modules.scanner.services.ai_analysis_service import (
    AIAnalysisService,
    ScanContext,
    ScannerFinding,
)
from app.services.ai import (
    AIConnectionError,
    AIParsingError,
    AIService,
    AIServiceError,
    AnalysisType,
    ConfidenceLevel,
    ModelNotConfiguredError,
    ParsedResponse,
    SeverityLevel,
    VulnerabilityFinding,
)


@pytest.fixture
def mock_ai_service() -> Mock:
    """Create a mock AIService."""
    service = Mock(spec=AIService)

    # SQL Injection finding
    sql_finding = VulnerabilityFinding(
        title="SQL Injection",
        description="SQL injection vulnerability found",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        affected_component="Login Form",
        remediation="Use parameterized queries",
        cve_id="CVE-2024-1234",
        references=["https://example.com"],
    )
    sql_response = ParsedResponse(
        analysis_type=AnalysisType.SQL_INJECTION,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[sql_finding],
        summary="Found 1 vulnerability",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )

    # XSS finding
    xss_finding = VulnerabilityFinding(
        title="XSS Vulnerability",
        description="Cross-site scripting vulnerability found",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        affected_component="Search Form",
        remediation="Encode user input",
        references=["https://example.com"],
    )
    xss_response = ParsedResponse(
        analysis_type=AnalysisType.XSS,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[xss_finding],
        summary="Found 1 XSS vulnerability",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )

    # Reverse Engineering finding
    re_finding = VulnerabilityFinding(
        title="Buffer Overflow",
        description="Buffer overflow vulnerability found",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.MEDIUM,
        affected_component="Function X",
        remediation="Add bounds checking",
    )
    re_response = ParsedResponse(
        analysis_type=AnalysisType.REVERSE_ENGINEERING,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[re_finding],
        summary="Found 1 reverse engineering issue",
        confidence=ConfidenceLevel.MEDIUM,
        is_json=True,
    )

    # Malware finding
    malware_finding = VulnerabilityFinding(
        title="Suspicious Registry Key",
        description="Malware detected",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        affected_component="Registry",
        remediation="Remove registry key",
    )
    malware_response = ParsedResponse(
        analysis_type=AnalysisType.MALWARE_ANALYSIS,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[malware_finding],
        summary="Found 1 malware indicator",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )

    # Generic finding for vulnerability explanation
    generic_response = ParsedResponse(
        analysis_type=AnalysisType.VULNERABILITY_EXPLANATION,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[sql_finding],
        summary="Vulnerability explained",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )

    # Security report
    report_response = ParsedResponse(
        analysis_type=AnalysisType.SECURITY_REPORT,
        raw_text="Raw response",
        cleaned_text="Cleaned response",
        findings=[sql_finding, xss_finding],
        summary="Security report generated",
        confidence=ConfidenceLevel.HIGH,
        is_json=True,
    )

    service.generate_sql_analysis.return_value = sql_response
    service.generate_xss_analysis.return_value = xss_response
    service.generate_reverse_engineering.return_value = re_response
    service.generate_malware_analysis.return_value = malware_response
    service.generate_security_report.return_value = report_response
    service.generate_vulnerability_explanation.return_value = generic_response

    return service


@pytest.fixture
def sample_finding() -> ScannerFinding:
    """Create a sample scanner finding."""
    return ScannerFinding(
        vulnerability_type="sql_injection",
        severity="high",
        description="SQL injection vulnerability in login form",
        location="http://test.com/login?id=1",
        evidence="' OR '1'='1",
        confidence="high",
        details={"parameter": "id", "payload": "' OR '1'='1"},
    )


@pytest.fixture
def sample_xss_finding() -> ScannerFinding:
    """Create a sample XSS finding."""
    return ScannerFinding(
        vulnerability_type="xss",
        severity="medium",
        description="Reflected XSS in search parameter",
        location="http://test.com/search?q=test",
        evidence="<script>alert('xss')</script>",
        confidence="high",
    )


@pytest.fixture
def sample_command_injection_finding() -> ScannerFinding:
    """Create a sample command injection finding."""
    return ScannerFinding(
        vulnerability_type="command_injection",
        severity="critical",
        description="Command injection in file parameter",
        location="http://test.com/exec?cmd=id",
        evidence="; ls -la",
        confidence="high",
    )


@pytest.fixture
def sample_path_traversal_finding() -> ScannerFinding:
    """Create a sample path traversal finding."""
    return ScannerFinding(
        vulnerability_type="path_traversal",
        severity="high",
        description="Path traversal in file parameter",
        location="http://test.com/file?path=../../etc/passwd",
        evidence="../../etc/passwd",
        confidence="medium",
    )


@pytest.fixture
def sample_ssrf_finding() -> ScannerFinding:
    """Create a sample SSRF finding."""
    return ScannerFinding(
        vulnerability_type="ssrf",
        severity="high",
        description="SSRF in url parameter",
        location="http://test.com/fetch?url=http://internal",
        evidence="http://169.254.169.254/latest/meta-data/",
        confidence="high",
    )


@pytest.fixture
def sample_context() -> ScanContext:
    """Create a sample scan context."""
    return ScanContext(
        url="http://test.com/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        payload="id=1' OR '1'='1",
        evidence="SQL error: ORA-01756",
        status_code=500,
        response_body="ORA-01756: quoted string not properly terminated",
        scanner_module="sql_injection_scanner",
    )


@pytest.fixture
def ai_analysis_service(mock_ai_service: Mock) -> AIAnalysisService:
    """Create an AIAnalysisService instance with mocks."""
    return AIAnalysisService(
        ai_service=mock_ai_service,
        enabled=True,
        cache_analyses=True,
    )


class TestInitialization:
    """Tests for AIAnalysisService initialization."""

    def test_initialization(self, mock_ai_service: Mock) -> None:
        """Test service initialization."""
        service = AIAnalysisService(
            ai_service=mock_ai_service,
            enabled=True,
            cache_analyses=True,
        )
        assert service._ai_service == mock_ai_service
        assert service._enabled is True
        assert service._cache_analyses is True
        assert service._analysis_cache == {}
        assert service._processed_findings == set()

    def test_initialization_with_logger(self, mock_ai_service: Mock) -> None:
        """Test initialization with custom logger."""
        import logging

        logger = logging.getLogger("test_logger")
        service = AIAnalysisService(
            ai_service=mock_ai_service,
            logger=logger,
        )
        assert service._logger == logger


class TestCacheAndEnabled:
    """Tests for cache and enabled state."""

    def test_clear_cache(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test clearing the cache."""
        ai_analysis_service._analysis_cache["key"] = "value"
        ai_analysis_service._processed_findings.add("key")

        ai_analysis_service.clear_cache()

        assert ai_analysis_service._analysis_cache == {}
        assert ai_analysis_service._processed_findings == set()

    def test_get_cache_stats(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test getting cache statistics."""
        ai_analysis_service._analysis_cache["key1"] = "value"
        ai_analysis_service._analysis_cache["key2"] = "value"
        ai_analysis_service._processed_findings.add("key1")

        stats = ai_analysis_service.get_cache_stats()

        assert stats["cached_analyses"] == 2
        assert stats["processed_findings"] == 1
        assert stats["cache_enabled"] is True
        assert stats["analysis_enabled"] is True

    def test_is_enabled(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test is_enabled method."""
        assert ai_analysis_service.is_enabled() is True

        ai_analysis_service.set_enabled(False)
        assert ai_analysis_service.is_enabled() is False

    def test_set_enabled(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test set_enabled method."""
        ai_analysis_service.set_enabled(False)
        assert ai_analysis_service._enabled is False

        ai_analysis_service.set_enabled(True)
        assert ai_analysis_service._enabled is True


class TestContextPreparation:
    """Tests for context preparation."""

    def test_prepare_scan_context(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test preparing scan context."""
        context = ScanContext(
            url="http://test.com",
            method="GET",
            headers={"User-Agent": "SentinelAI"},
            payload="test=1",
            evidence="Test evidence",
            status_code=200,
            response_body="Test response",
            scanner_module="test_module",
        )

        prepared = ai_analysis_service._prepare_scan_context(context)

        assert prepared["url"] == "http://test.com"
        assert prepared["method"] == "GET"
        assert "User-Agent" in prepared["headers"]
        assert prepared["payload"] == "test=1"
        assert prepared["evidence"] == "Test evidence"
        assert prepared["status_code"] == 200
        assert prepared["scanner_module"] == "test_module"

    def test_prepare_scan_context_empty(
        self, ai_analysis_service: AIAnalysisService
    ) -> None:
        """Test preparing scan context with empty values."""
        context = ScanContext(url="http://test.com")

        prepared = ai_analysis_service._prepare_scan_context(context)

        assert prepared["headers"] == "{}"
        assert prepared["payload"] == "None"
        assert prepared["evidence"] == "None"
        assert prepared["status_code"] == "Unknown"
        assert prepared["response_body"] == "None"


class TestAnalysisMethods:
    """Tests for analysis methods."""

    def test_analyze_sql_injection(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test SQL injection analysis."""
        result = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            sample_context,
        )
        assert result is not None
        assert result.analysis_type == AnalysisType.SQL_INJECTION

    def test_analyze_xss(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_xss_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test XSS analysis."""
        result = ai_analysis_service.analyze_xss(
            sample_xss_finding,
            sample_context,
        )
        assert result is not None
        assert result.analysis_type == AnalysisType.XSS

    def test_analyze_command_injection(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_command_injection_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test command injection analysis."""
        result = ai_analysis_service.analyze_command_injection(
            sample_command_injection_finding,
            sample_context,
        )
        assert result is not None

    def test_analyze_path_traversal(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_path_traversal_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test path traversal analysis."""
        result = ai_analysis_service.analyze_path_traversal(
            sample_path_traversal_finding,
            sample_context,
        )
        assert result is not None

    def test_analyze_ssrf(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_ssrf_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test SSRF analysis."""
        result = ai_analysis_service.analyze_ssrf(
            sample_ssrf_finding,
            sample_context,
        )
        assert result is not None

    def test_analyze_reverse_engineering(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test reverse engineering analysis."""
        result = ai_analysis_service.analyze_reverse_engineering(
            sample_finding,
            sample_context,
        )
        assert result is not None

    def test_analyze_malware(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test malware analysis."""
        result = ai_analysis_service.analyze_malware(
            sample_finding,
            sample_context,
        )
        assert result is not None

    def test_generate_security_report(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test security report generation."""
        findings = [sample_finding, sample_finding]
        result = ai_analysis_service.generate_security_report(
            findings,
            sample_context,
        )
        assert result is not None

    def test_explain_vulnerability(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test vulnerability explanation."""
        result = ai_analysis_service.explain_vulnerability(
            sample_finding,
            sample_context,
        )
        assert result is not None


class TestEmptyFindings:
    """Tests for empty findings handling."""

    def test_empty_findings_sql(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test SQL analysis with empty findings."""
        finding = ScannerFinding(
            vulnerability_type="sql_injection",
            severity="low",
            description="",
            location="",
        )
        context = ScanContext(url="http://test.com")

        result = ai_analysis_service.analyze_sql_injection(finding, context)
        assert result is not None

    def test_empty_findings_security_report(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_context: ScanContext,
    ) -> None:
        """Test security report with empty findings list."""
        result = ai_analysis_service.generate_security_report([], sample_context)
        assert result is not None
        assert result.summary == "No analysis performed - no findings provided"


class TestAIDisabled:
    """Tests when AI is disabled."""

    def test_ai_disabled(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test analysis when AI is disabled."""
        ai_analysis_service.set_enabled(False)

        result = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            sample_context,
        )

        assert result is not None
        assert result.summary == "No analysis performed - no findings provided"
        assert result.findings == []

    def test_ai_disabled_report(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_context: ScanContext,
    ) -> None:
        """Test report generation when AI is disabled."""
        ai_analysis_service.set_enabled(False)
        findings = [
            ScannerFinding(
                vulnerability_type="sql_injection",
                severity="high",
                description="Test",
                location="test",
            )
        ]

        result = ai_analysis_service.generate_security_report(findings, sample_context)

        assert result is not None
        assert result.summary == "No analysis performed - no findings provided"


class TestDuplicateAnalysis:
    """Tests for duplicate analysis prevention."""

    def test_duplicate_analysis(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test that duplicate analyses are skipped."""
        result1 = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            sample_context,
        )
        assert result1 is not None

        result2 = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            sample_context,
        )
        assert result2 is not None
        assert result2.summary == "No analysis performed - no findings provided"

    def test_duplicate_analysis_different_context(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
    ) -> None:
        """Test that different contexts create different cache keys."""
        context1 = ScanContext(url="http://test1.com")
        context2 = ScanContext(url="http://test2.com")

        result1 = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            context1,
        )
        assert result1 is not None

        result2 = ai_analysis_service.analyze_sql_injection(
            sample_finding,
            context2,
        )
        assert result2 is not None

    def test_duplicate_with_cache_disabled(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test duplicate analysis when cache is disabled."""
        service = AIAnalysisService(
            ai_service=mock_ai_service,
            cache_analyses=False,
        )

        result1 = service.analyze_sql_injection(sample_finding, sample_context)
        result2 = service.analyze_sql_injection(sample_finding, sample_context)

        assert result1 is not None
        assert result2 is not None


class TestExceptionTranslation:
    """Tests for exception translation."""

    def test_model_not_configured_error(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test ModelNotConfiguredError translation."""
        mock_ai_service.generate_sql_analysis.side_effect = ModelNotConfiguredError(
            "No model"
        )
        service = AIAnalysisService(ai_service=mock_ai_service)

        with pytest.raises(ScannerAINotConfiguredError) as exc_info:
            service.analyze_sql_injection(sample_finding, sample_context)

        assert "AI service not configured" in str(exc_info.value)

    def test_ai_connection_error(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test AIConnectionError translation."""
        mock_ai_service.generate_sql_analysis.side_effect = AIConnectionError(
            "Connection failed"
        )
        service = AIAnalysisService(ai_service=mock_ai_service)

        with pytest.raises(ScannerAIConnectionError) as exc_info:
            service.analyze_sql_injection(sample_finding, sample_context)

        assert "Connection to AI service failed" in str(exc_info.value)

    def test_ai_parsing_error(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test AIParsingError translation."""
        mock_ai_service.generate_sql_analysis.side_effect = AIParsingError(
            "Parse failed"
        )
        service = AIAnalysisService(ai_service=mock_ai_service)

        with pytest.raises(ScannerAIParsingError) as exc_info:
            service.analyze_sql_injection(sample_finding, sample_context)

        assert "Failed to parse AI response" in str(exc_info.value)

    def test_generic_ai_service_error(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test generic AIServiceError translation."""
        mock_ai_service.generate_sql_analysis.side_effect = AIServiceError(
            "Generic error"
        )
        service = AIAnalysisService(ai_service=mock_ai_service)

        with pytest.raises(ScannerAIAnalysisError) as exc_info:
            service.analyze_sql_injection(sample_finding, sample_context)

        assert "AI service error" in str(exc_info.value)

    def test_unexpected_error(
        self,
        mock_ai_service: Mock,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test unexpected error handling."""
        mock_ai_service.generate_sql_analysis.side_effect = ValueError("Unexpected")
        service = AIAnalysisService(ai_service=mock_ai_service)

        with pytest.raises(ScannerAIAnalysisError) as exc_info:
            service.analyze_sql_injection(sample_finding, sample_context)

        assert "Unexpected error" in str(exc_info.value)


class TestSeverityAndConfidenceConversion:
    """Tests for severity and confidence conversion."""

    def test_severity_conversion(self, ai_analysis_service: AIAnalysisService) -> None:
        """Test severity level conversion."""
        assert (
            ai_analysis_service._severity_to_ai_level("critical")
            == SeverityLevel.CRITICAL
        )
        assert ai_analysis_service._severity_to_ai_level("high") == SeverityLevel.HIGH
        assert (
            ai_analysis_service._severity_to_ai_level("medium") == SeverityLevel.MEDIUM
        )
        assert ai_analysis_service._severity_to_ai_level("low") == SeverityLevel.LOW
        assert ai_analysis_service._severity_to_ai_level("info") == SeverityLevel.INFO
        assert (
            ai_analysis_service._severity_to_ai_level("unknown") == SeverityLevel.MEDIUM
        )

    def test_confidence_conversion(
        self, ai_analysis_service: AIAnalysisService
    ) -> None:
        """Test confidence level conversion."""
        assert (
            ai_analysis_service._confidence_to_ai_level("high") == ConfidenceLevel.HIGH
        )
        assert (
            ai_analysis_service._confidence_to_ai_level("medium")
            == ConfidenceLevel.MEDIUM
        )
        assert ai_analysis_service._confidence_to_ai_level("low") == ConfidenceLevel.LOW
        assert (
            ai_analysis_service._confidence_to_ai_level("unknown")
            == ConfidenceLevel.MEDIUM
        )


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_analysis(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test concurrent analysis calls."""

        def analyze() -> None:
            result = ai_analysis_service.analyze_sql_injection(
                sample_finding,
                sample_context,
            )
            assert result is not None

        threads = []
        for _ in range(10):
            t = threading.Thread(target=analyze)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def test_concurrent_cache_access(
        self,
        ai_analysis_service: AIAnalysisService,
        sample_finding: ScannerFinding,
        sample_context: ScanContext,
    ) -> None:
        """Test concurrent cache access."""

        def clear_cache() -> None:
            ai_analysis_service.clear_cache()

        def analyze() -> None:
            ai_analysis_service.analyze_sql_injection(
                sample_finding,
                sample_context,
            )

        threads = []
        for i in range(5):
            if i % 2 == 0:
                t = threading.Thread(target=clear_cache)
            else:
                t = threading.Thread(target=analyze)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()


class TestScannerFindingAndContext:
    """Tests for ScannerFinding and ScanContext dataclasses."""

    def test_scanner_finding_creation(self) -> None:
        """Test ScannerFinding creation."""
        finding = ScannerFinding(
            vulnerability_type="sql_injection",
            severity="high",
            description="Test description",
            location="http://test.com",
            evidence="Test evidence",
            confidence="high",
            details={"key": "value"},
        )
        assert finding.vulnerability_type == "sql_injection"
        assert finding.severity == "high"
        assert finding.description == "Test description"
        assert finding.location == "http://test.com"
        assert finding.evidence == "Test evidence"
        assert finding.confidence == "high"
        assert finding.details == {"key": "value"}

    def test_scanner_finding_to_dict(self) -> None:
        """Test ScannerFinding to_dict conversion."""
        finding = ScannerFinding(
            vulnerability_type="sql_injection",
            severity="high",
            description="Test description",
            location="http://test.com",
            evidence="Test evidence",
        )
        data = finding.to_dict()
        assert data["vulnerability_type"] == "sql_injection"
        assert data["severity"] == "high"
        assert data["description"] == "Test description"

    def test_scan_context_creation(self) -> None:
        """Test ScanContext creation."""
        context = ScanContext(
            url="http://test.com",
            method="POST",
            headers={"Content-Type": "application/json"},
            payload='{"test": "value"}',
            evidence="Test evidence",
            status_code=200,
            response_body='{"success": true}',
            scanner_module="test_module",
            additional_data={"extra": "data"},
        )
        assert context.url == "http://test.com"
        assert context.method == "POST"
        assert context.headers == {"Content-Type": "application/json"}
        assert context.payload == '{"test": "value"}'
        assert context.evidence == "Test evidence"
        assert context.status_code == 200
        assert context.scanner_module == "test_module"

    def test_scan_context_to_dict(self) -> None:
        """Test ScanContext to_dict conversion."""
        context = ScanContext(
            url="http://test.com",
            method="POST",
            headers={"Content-Type": "application/json"},
            status_code=200,
        )
        data = context.to_dict()
        assert data["url"] == "http://test.com"
        assert data["method"] == "POST"
        assert data["headers"] == {"Content-Type": "application/json"}
        assert data["status_code"] == 200


class TestExceptions:
    """Tests for custom exceptions."""

    def test_scanner_ai_analysis_error(self) -> None:
        """Test ScannerAIAnalysisError."""
        error = ScannerAIAnalysisError("Test error", details={"key": "value"})
        assert error.message == "Test error"
        assert error.details == {"key": "value"}
        assert str(error) == "Test error - Details: {'key': 'value'}"

    def test_scanner_ai_analysis_error_no_details(self) -> None:
        """Test ScannerAIAnalysisError without details."""
        error = ScannerAIAnalysisError("Test error")
        assert str(error) == "Test error"

    def test_scanner_ai_not_configured_error(self) -> None:
        """Test ScannerAINotConfiguredError."""
        error = ScannerAINotConfiguredError("Not configured")
        assert isinstance(error, ScannerAIAnalysisError)

    def test_scanner_ai_connection_error(self) -> None:
        """Test ScannerAIConnectionError."""
        error = ScannerAIConnectionError("Connection error")
        assert isinstance(error, ScannerAIAnalysisError)

    def test_scanner_ai_parsing_error(self) -> None:
        """Test ScannerAIParsingError."""
        error = ScannerAIParsingError("Parsing error")
        assert isinstance(error, ScannerAIAnalysisError)

    def test_scanner_ai_report_error(self) -> None:
        """Test ScannerAIReportError."""
        error = ScannerAIReportError("Report error")
        assert isinstance(error, ScannerAIAnalysisError)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
