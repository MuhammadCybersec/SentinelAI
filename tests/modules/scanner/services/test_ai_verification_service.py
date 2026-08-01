"""
Tests for AI Verification Service.
"""

from unittest.mock import MagicMock

import pytest

from app.modules.scanner.services.ai_verification_service import (
    AIVerificationService,
    CVSSInfo,
    SeverityLevel,
    VerificationConfig,
    VerificationContext,
    VerificationResult,
    VerificationStatus,
)


class TestAIVerificationService:
    """Tests for AIVerificationService."""

    @pytest.fixture
    def service(self):
        """Create AIVerificationService instance with mocked AI service."""
        # Create mock AI service
        mock_ai_service = MagicMock()
        mock_ai_service.analyze_finding = MagicMock()

        # Create service and inject mock
        service = AIVerificationService()
        service._ai_service = mock_ai_service
        return service

    @pytest.fixture
    def sample_finding(self):
        """Sample finding data."""
        return {
            "id": "finding-001",
            "type": "xss",
            "payload": "<script>alert('xss')</script>",
            "location": "/test",
            "severity": "high",
        }

    @pytest.fixture
    def sample_context(self):
        """Sample verification context."""
        return VerificationContext(
            target="https://example.com",
            finding_type="xss",
            source_code="<html><body><script>test</script></body></html>",
            request_data={"url": "/test", "method": "GET"},
            environment={"env": "test"},
        )

    def test_init_defaults(self, service):
        """Test initialization with defaults."""
        assert service._ai_service is not None
        assert service._config is not None
        assert service._config.MIN_CONFIDENCE_THRESHOLD == 60.0
        assert service._config.FALSE_POSITIVE_THRESHOLD == 30.0
        assert service._cache_max_size == 1000

    def test_verify_finding_success(self, service, sample_finding):
        """Test successful finding verification."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={
                "confidence": 85.0,
                "explanation": "This is a valid XSS vulnerability",
                "recommendations": ["Encode output", "Use CSP headers"],
                "severity": "high",
                "cwe_id": "CWE-79",
            }
        )

        result = service.verify_finding(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
        )

        assert result.verified is True
        assert result.confidence == 85.0
        assert result.status == VerificationStatus.VERIFIED
        assert result.severity == SeverityLevel.HIGH
        assert result.cwe is not None
        assert result.cwe.id == "CWE-79"
        assert len(result.recommendations) > 0

    def test_verify_finding_false_positive(self, service, sample_finding):
        """Test false positive detection."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={
                "confidence": 20.0,
                "explanation": "This is likely a false positive",
                "false_positive_reason": "No actual vulnerability found",
            }
        )

        result = service.verify_finding(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
        )

        assert result.false_positive is True
        assert result.verified is False
        assert result.status == VerificationStatus.FALSE_POSITIVE
        assert result.confidence < 30.0

    def test_verify_finding_with_context(self, service, sample_finding, sample_context):
        """Test verification with context."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 90.0, "explanation": "Verified with context"}
        )

        result = service.verify_finding(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
            context=sample_context,
        )

        assert result.verified is True
        assert result.confidence >= 90.0

    def test_verify_finding_with_retry(self, service, sample_finding):
        """Test verification with retry on failure."""
        call_count = 0

        def mock_analyze(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Temporary error")
            return {"confidence": 75.0}

        service._ai_service.analyze_finding = MagicMock(side_effect=mock_analyze)

        result = service.verify_finding(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
            retry_count=2,
        )

        assert call_count == 2
        assert result.verified is True

    def test_verify_finding_timeout(self, service, sample_finding):
        """Test verification timeout handling."""

        def mock_analyze(*args, **kwargs):
            import time

            time.sleep(0.1)
            return {"confidence": 75.0}

        service._ai_service.analyze_finding = MagicMock(side_effect=mock_analyze)

        result = service.verify_finding(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
            timeout=1.0,
        )

        assert result is not None

    def test_calculate_confidence(self, service, sample_finding):
        """Test confidence calculation."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 80.0}
        )

        confidence = service.calculate_confidence(sample_finding)

        assert 0 <= confidence <= 100
        assert confidence >= 50.0

    def test_detect_false_positive(self, service, sample_finding):
        """Test false positive detection."""
        # Low confidence should trigger false positive
        analysis_result = {"confidence": 20.0}

        is_fp = service.detect_false_positive(
            sample_finding, analysis_result=analysis_result
        )
        assert is_fp is True

        # High confidence should not trigger false positive
        analysis_result = {"confidence": 90.0}

        is_fp = service.detect_false_positive(
            sample_finding, analysis_result=analysis_result
        )
        assert is_fp is False

        # Also test with is_false_positive flag
        analysis_result = {"confidence": 80.0, "is_false_positive": True}

        is_fp = service.detect_false_positive(
            sample_finding, analysis_result=analysis_result
        )
        assert is_fp is True

    def test_verify_batch(self, service):
        """Test batch verification."""
        findings = [
            {"id": f"finding-{i}", "type": "xss", "payload": f"test{i}"}
            for i in range(3)
        ]

        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 80.0}
        )

        results = service.verify_batch(
            findings=findings, scanner_name="xss_scanner", target="https://example.com"
        )

        assert len(results) == 3
        assert all(isinstance(r, VerificationResult) for r in results)

    def test_verify_batch_empty(self, service):
        """Test batch verification with empty list."""
        results = service.verify_batch([], "scanner", "target")
        assert results == []

    def test_verify_batch_too_large(self, service):
        """Test batch verification with too many items."""
        findings = [
            {"id": f"f{i}"} for i in range(VerificationConfig.MAX_BATCH_SIZE + 1)
        ]

        with pytest.raises(ValueError, match="exceeds maximum"):
            service.verify_batch(findings, "scanner", "target")

    @pytest.mark.asyncio
    async def test_verify_async(self, service, sample_finding):
        """Test async verification."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 85.0}
        )

        result = await service.verify_async(
            scanner_name="xss_scanner",
            finding=sample_finding,
            target="https://example.com",
        )

        assert result.verified is True
        assert result.confidence >= 85.0

    def test_export_to_json(self, service):
        """Test JSON export."""
        result = VerificationResult(
            finding_id="f-001",
            scanner_name="test",
            verified=True,
            confidence=80.0,
            status=VerificationStatus.VERIFIED,
            severity=SeverityLevel.HIGH,
            recommendations=["Fix this"],
        )

        json_str = service.export_to_json(result)
        assert json_str is not None
        assert "f-001" in json_str
        assert "VERIFIED" in json_str

    def test_get_statistics(self, service, sample_finding):
        """Test statistics retrieval."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 80.0}
        )

        service.verify_finding("scanner", sample_finding, "target")
        stats = service.get_statistics()

        assert stats.total == 1
        assert stats.verified == 1
        assert stats.avg_confidence >= 80.0

    def test_clear_cache(self, service, sample_finding):
        """Test cache clearing."""
        service._ai_service.analyze_finding = MagicMock(
            return_value={"confidence": 80.0}
        )

        # Add to cache
        service.verify_finding("scanner", sample_finding, "target")
        assert len(service._cache) > 0

        # Clear cache
        service.clear_cache()
        assert len(service._cache) == 0

    def test_shutdown(self, service):
        """Test shutdown."""
        service.shutdown()
        assert service._running is False
        assert len(service._async_tasks) == 0

    def test_cvss_calculation(self, service):
        """Test CVSS calculation."""
        cvss = service._calculate_cvss(
            {"type": "xss", "severity": "high"},
            SeverityLevel.HIGH,
            {"confidence": 80.0},
        )

        assert isinstance(cvss, CVSSInfo)
        assert 7.0 <= cvss.score <= 8.9
        assert cvss.vector != ""
        assert cvss.metrics is not None

    def test_cwe_mapping(self, service):
        """Test CWE mapping."""
        cwe = service._get_cwe_info({"type": "xss", "cwe_id": "CWE-79"}, {})

        assert cwe is not None
        assert cwe.id == "CWE-79"
        assert cwe.name == "Cross-site Scripting (XSS)"

    def test_severity_determination(self, service):
        """Test severity determination."""
        # From finding
        severity = service._determine_severity({"severity": "critical"}, {})
        assert severity == SeverityLevel.CRITICAL

        # From analysis
        severity = service._determine_severity({}, {"severity": "low"})
        assert severity == SeverityLevel.LOW

        # Default
        severity = service._determine_severity({}, {})
        assert severity == SeverityLevel.NONE
